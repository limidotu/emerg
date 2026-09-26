FROM kalilinux/kali-rolling
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 curl nmap nuclei sqlmap ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 emerg && useradd --uid 10001 --gid emerg --no-create-home emerg
COPY src/emergent_kali/runner_runtime.py /opt/emerg/runtime.py
COPY services/kali-runner/templates /opt/emerg/templates
USER 10001:10001
WORKDIR /workspace
CMD ["python3", "/opt/emerg/runtime.py", "serve"]

