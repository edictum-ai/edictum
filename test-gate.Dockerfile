FROM python:3.12-slim

WORKDIR /edictum

# Install the package with gate + dev deps
COPY . .
RUN pip install -e ".[gate,dev]" --quiet

# Create a fake home for gate config (not your real ~)
ENV HOME=/home/tester
RUN mkdir -p /home/tester

# Copy the test script
COPY test-gate-docker.sh /test-gate-docker.sh
RUN chmod +x /test-gate-docker.sh

CMD ["/test-gate-docker.sh"]
