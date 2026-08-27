# Actual Yeti container
#
# -slim avoids buildpack-deps, whose development headers (libpq among them) are
# unused by Yeti and only add size and scan surface.
FROM python:3.13-slim AS yeti

# gcc and libc6-dev are required to compile yara-python, which publishes no
# wheel for this platform. git is required to resolve a dependency pinned to a
# git+https URL.
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    git \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

ADD . /app

WORKDIR /app
RUN cp yeti.conf.sample yeti.conf
RUN cp ./extras/docker/docker-entrypoint.sh /docker-entrypoint.sh

# Upgrade pip
RUN pip3 install --upgrade pip && pip3 install uv

# Install yeti
RUN uv sync --group plugins

# Bake in the embedding model chromadb's default embedding function uses.
# It is otherwise fetched from the network on first use, which fails on
# deployments without internet access. Warming it through chromadb rather than
# downloading the archive directly verifies the SHA256 chromadb pins and keeps
# the model in step with the resolved chromadb version. Only the extracted
# files are looked up at runtime, so the archive is dropped: keeping it would
# double the ~88MB cost for nothing.
#
# The cache path is derived from $HOME with no override, so this must be
# written by the same user that runs Yeti.
RUN uv run python -c \
    "from chromadb.utils.embedding_functions import DefaultEmbeddingFunction; DefaultEmbeddingFunction()(['warmup'])" \
    && rm -f /root/.cache/chroma/onnx_models/all-MiniLM-L6-v2/onnx.tar.gz

ENV PYTHONPATH /app

ENTRYPOINT ["/docker-entrypoint.sh"]
