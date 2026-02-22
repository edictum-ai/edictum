# Change Control Patterns

Change control contracts enforce process requirements around high-impact operations: ticket references, approval gates, blast radius limits, dry-run requirements, and SQL safety. These are primarily preconditions that block before execution.

---

## Ticket Requirement for Production Changes

Require a ticket reference on every production deployment. This ensures traceability -- every change can be linked back to an approved request.

**When to use:** Your organization requires that production changes are traceable to tickets in a project management system (Jira, Linear, etc.). The `principal.ticket_ref` field carries the ticket ID.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: ticket-requirement

    defaults:
      mode: enforce

    contracts:
      - id: prod-requires-ticket
        type: pre
        tool: deploy_service
        when:
          all:
            - environment: { equals: production }
            - principal.ticket_ref: { exists: false }
        then:
          effect: deny
          message: "Production deployments require a ticket reference. Attach a ticket_ref to the principal."
          tags: [change-control, compliance]

      - id: prod-requires-ticket-for-db
        type: pre
        tool: query_database
        when:
          all:
            - environment: { equals: production }
            - args.query: { matches: '\\b(INSERT|UPDATE|DELETE|ALTER)\\b' }
            - principal.ticket_ref: { exists: false }
        then:
          effect: deny
          message: "Production write queries require a ticket reference."
          tags: [change-control, compliance]
    ```

=== "Python"

    ```python
    from edictum import Verdict, precondition

    @precondition("deploy_service")
    def prod_requires_ticket(envelope):
        if envelope.environment != "production":
            return Verdict.pass_()
        if not envelope.principal or not envelope.principal.ticket_ref:
            return Verdict.fail(
                "Production deployments require a ticket reference. "
                "Attach a ticket_ref to the principal."
            )
        return Verdict.pass_()

    @precondition("query_database")
    def prod_requires_ticket_for_db(envelope):
        import re
        if envelope.environment != "production":
            return Verdict.pass_()
        query = envelope.args.get("query", "")
        if re.search(r'\b(INSERT|UPDATE|DELETE|ALTER)\b', query):
            if not envelope.principal or not envelope.principal.ticket_ref:
                return Verdict.fail("Production write queries require a ticket reference.")
        return Verdict.pass_()
    ```

**Gotchas:**
- `exists: false` checks whether the field is absent or null. It does not validate that the ticket reference is a real ticket ID. Your application should validate the ticket against your project management API before attaching it to the principal.
- Non-production environments are unaffected because the `all` combinator short-circuits: if `environment` is not `production`, the entire expression evaluates to `false` and the contract does not fire.

---

## Role-Based Approval Gates

Restrict high-impact tools to senior roles. This pattern is the simplest form of an approval gate -- only users with the right role can proceed.

**When to use:** Certain operations (deploys, migrations, infrastructure changes) should only be performed by experienced operators.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: approval-gates

    defaults:
      mode: enforce

    contracts:
      - id: deploy-requires-senior-role
        type: pre
        tool: deploy_service
        when:
          all:
            - environment: { equals: production }
            - principal.role: { not_in: [admin, sre] }
        then:
          effect: deny
          message: "Production deploys require admin or sre role. Current role: {principal.role}."
          tags: [change-control, production]

      - id: migration-requires-admin
        type: pre
        tool: query_database
        when:
          all:
            - args.query: { matches: '\\b(ALTER|CREATE|DROP)\\b' }
            - principal.role: { not_equals: admin }
        then:
          effect: deny
          message: "DDL operations require admin role."
          tags: [change-control, database]
    ```

=== "Python"

    ```python
    import re
    from edictum import Verdict, precondition

    @precondition("deploy_service")
    def deploy_requires_senior_role(envelope):
        if envelope.environment != "production":
            return Verdict.pass_()
        if not envelope.principal or envelope.principal.role not in ("admin", "sre"):
            role = envelope.principal.role if envelope.principal else "none"
            return Verdict.fail(
                f"Production deploys require admin or sre role. Current role: {role}."
            )
        return Verdict.pass_()

    @precondition("query_database")
    def migration_requires_admin(envelope):
        query = envelope.args.get("query", "")
        if re.search(r'\b(ALTER|CREATE|DROP)\b', query):
            if not envelope.principal or envelope.principal.role != "admin":
                return Verdict.fail("DDL operations require admin role.")
        return Verdict.pass_()
    ```

**Gotchas:**
- If no principal is attached, `principal.role` is missing, the leaf evaluates to `false`, and the `all` block evaluates to `false`. The contract does not fire. Add a `principal.role: { exists: false }` contract to catch unauthenticated calls.

---

## Human Approval Gate

Pause high-impact tool calls and wait for a human to approve or deny them. Unlike role-based gates (which deny immediately if the role is wrong), approval gates pause the pipeline and request explicit human sign-off before proceeding.

**When to use:** Destructive operations (database drops, production deploys, bulk deletes) where even authorized users should confirm intent before the tool executes.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: approval-gates

    defaults:
      mode: enforce

    contracts:
      - id: delete-requires-approval
        type: pre
        tool: "db_*"
        when:
          args.query:
            matches: '\bDELETE\b'
        then:
          effect: approve
          message: "DELETE query requires human approval: {args.query}"
          timeout: 120
          timeout_effect: deny
    ```

=== "Python"

    ```python
    from edictum import Edictum, LocalApprovalBackend

    guard = Edictum.from_yaml(
        "contracts.yaml",
        approval_backend=LocalApprovalBackend(),
    )

    # When the contract fires, the pipeline:
    # 1. Calls approval_backend.request_approval(...)
    # 2. Waits up to `timeout` seconds for a decision
    # 3. If approved -> tool executes normally
    # 4. If denied -> EdictumDenied is raised
    # 5. If timeout -> applies timeout_effect (deny or allow)
    ```

**Three outcomes:**

| Outcome | What happens | Audit event |
|---------|-------------|-------------|
| Approved | Tool call proceeds, `on_allow` fires | `CALL_APPROVAL_GRANTED` |
| Denied | `EdictumDenied` raised, `on_deny` fires | `CALL_APPROVAL_DENIED` |
| Timeout | Applies `timeout_effect` (default: deny) | `CALL_APPROVAL_TIMEOUT` |

**Gotchas:**
- If no `approval_backend` is configured on the `Edictum` instance, `effect: approve` raises `EdictumDenied` immediately with the message "Approval required but no approval backend configured."
- The `timeout` field is in seconds. The default (300s / 5 minutes) is generous for interactive workflows. Reduce it for automated pipelines.
- `timeout_effect: allow` should only be used when the timeout indicates the operation is safe to proceed (e.g., a low-risk change that just needs acknowledgement).
- The `tool: "db_*"` selector uses glob matching to cover all database tools. See [tool selectors](../../contracts/yaml-reference.md#precondition) in the YAML reference.

---

## Blast Radius Limits

Cap the scope of batch operations to prevent agents from making changes that are too large to review or roll back.

**When to use:** Your agent performs bulk operations (batch inserts, mass notifications, bulk updates) where an unbounded scope could cause widespread damage.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: blast-radius-limits

    defaults:
      mode: enforce

    contracts:
      - id: limit-batch-size
        type: pre
        tool: query_database
        when:
          args.batch_size: { gt: 500 }
        then:
          effect: deny
          message: "Batch size {args.batch_size} exceeds the limit of 500. Reduce the batch."
          tags: [change-control, blast-radius]

      - id: limit-notification-recipients
        type: pre
        tool: send_email
        when:
          args.recipient_count: { gt: 50 }
        then:
          effect: deny
          message: "Cannot send to more than 50 recipients at once. Split into smaller batches."
          tags: [change-control, blast-radius]
    ```

=== "Python"

    ```python
    from edictum import Verdict, precondition

    @precondition("query_database")
    def limit_batch_size(envelope):
        batch_size = envelope.args.get("batch_size", 0)
        if batch_size > 500:
            return Verdict.fail(
                f"Batch size {batch_size} exceeds the limit of 500. Reduce the batch."
            )
        return Verdict.pass_()

    @precondition("send_email")
    def limit_notification_recipients(envelope):
        count = envelope.args.get("recipient_count", 0)
        if count > 50:
            return Verdict.fail(
                "Cannot send to more than 50 recipients at once. Split into smaller batches."
            )
        return Verdict.pass_()
    ```

**Gotchas:**
- The `gt` operator requires the selector value to be a number. If `args.batch_size` is a string (e.g., `"500"`), the operator triggers a `policy_error` and the contract fires (fail-closed). Ensure your tools pass numeric arguments.
- Blast radius limits are a safety net, not a replacement for proper pagination in your tools.

---

## Dry-Run Requirements

Force agents to perform a dry-run before executing destructive production operations. The agent must verify the plan before executing it for real.

**When to use:** Production deployments, migrations, and infrastructure changes where you want the agent to preview the impact before committing.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: dry-run-requirement

    defaults:
      mode: enforce

    contracts:
      - id: prod-deploy-requires-dry-run
        type: pre
        tool: deploy_service
        when:
          all:
            - environment: { equals: production }
            - not:
                args.dry_run: { equals: true }
        then:
          effect: deny
          message: "Production deploys require dry_run=true first. Run a dry-run, verify output, then deploy."
          tags: [change-control, production]
    ```

=== "Python"

    ```python
    from edictum import Verdict, precondition

    @precondition("deploy_service")
    def prod_deploy_requires_dry_run(envelope):
        if envelope.environment != "production":
            return Verdict.pass_()
        if not envelope.args.get("dry_run", False):
            return Verdict.fail(
                "Production deploys require dry_run=true first. "
                "Run a dry-run, verify output, then deploy."
            )
        return Verdict.pass_()
    ```

**Gotchas:**
- This contract blocks all production deploys where `dry_run` is not `true`. The agent must make two calls: first with `dry_run=true`, then with `dry_run=false` (or omitted) after verifying the output. However, this contract will block the second call too. In practice, you would either remove the dry-run gate after verification or use a session-aware approach that checks whether a dry-run was already executed.
- The `not` combinator negates a single child expression. `not: { args.dry_run: { equals: true } }` fires when `dry_run` is either missing or not `true`.

---

## SQL Safety

Block dangerous SQL patterns and require bounded queries. This prevents agents from accidentally running DDL statements or unbounded SELECTs that could crash the database.

**When to use:** Your agent generates SQL from natural language or constructs queries dynamically. You want to prevent destructive DDL and ensure all queries have a LIMIT clause.

=== "YAML"

    ```yaml
    apiVersion: edictum/v1
    kind: ContractBundle

    metadata:
      name: sql-safety

    defaults:
      mode: enforce

    contracts:
      - id: block-ddl
        type: pre
        tool: query_database
        when:
          any:
            - args.query: { matches: '\\bDROP\\b' }
            - args.query: { matches: '\\bALTER\\b' }
            - args.query: { matches: '\\bTRUNCATE\\b' }
            - args.query: { matches: '\\bCREATE\\b' }
            - args.query: { matches: '\\bGRANT\\b' }
            - args.query: { matches: '\\bREVOKE\\b' }
        then:
          effect: deny
          message: "DDL statements are not allowed. This agent can only run SELECT queries."
          tags: [change-control, database, sql-safety]

      - id: require-limit-on-select
        type: pre
        tool: query_database
        when:
          all:
            - args.query: { matches: '\\bSELECT\\b' }
            - not:
                args.query: { matches: '\\bLIMIT\\b' }
        then:
          effect: deny
          message: "SELECT queries must include a LIMIT clause to prevent unbounded result sets."
          tags: [change-control, database, sql-safety]
    ```

=== "Python"

    ```python
    import re
    from edictum import Verdict, precondition

    @precondition("query_database")
    def block_ddl(envelope):
        query = (envelope.args.get("query") or "").upper()
        ddl_keywords = ["DROP", "ALTER", "TRUNCATE", "CREATE", "GRANT", "REVOKE"]
        for kw in ddl_keywords:
            if re.search(rf"\b{kw}\b", query):
                return Verdict.fail(
                    f"DDL statement '{kw}' is not allowed. "
                    "This agent can only run SELECT queries."
                )
        return Verdict.pass_()

    @precondition("query_database")
    def require_limit_on_select(envelope):
        query = (envelope.args.get("query") or "").upper()
        if "SELECT" in query and "LIMIT" not in query:
            return Verdict.fail(
                "SELECT queries must include a LIMIT clause "
                "to prevent unbounded result sets."
            )
        return Verdict.pass_()
    ```

**Gotchas:**
- Regex matching is case-sensitive by default. The patterns above match uppercase SQL keywords. If your agent generates lowercase SQL, add case-insensitive patterns or normalize the query before evaluation.
- The `LIMIT` check uses `matches` to search anywhere in the query string. A subquery with `LIMIT` in a comment would satisfy the check. For production use, consider a Python precondition that parses the SQL properly.
- These contracts protect against accidental DDL, not intentional abuse. A determined agent could encode SQL to bypass string matching. Defense in depth with database-level permissions is essential.
