FROM ubuntu:24.04

# Install approved tools during image build
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        iputils-ping \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd --create-home --shell /bin/bash student

# Give the student a temporary workspace
RUN mkdir -p /home/student/work && \
    chown -R student:student /home/student

USER student
WORKDIR /home/student

CMD ["/bin/bash"]