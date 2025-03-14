BIN_DIR:=bin
BINARY_PATH:=${BIN_DIR}/caretta
DOCKER_BIN:=docker
BPF2GO_BINARY := ${BIN_DIR}/bpf2go
BPF2GO_VERSION := 0.9.0
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UIDGID := $(shell gstat -c '%u:%g' ${REPODIR})
PROJECT_DIRNAME := $(shell basename ${REPODIR})
CILIUM_EBPF_DIRECTORY := /tmp/cilium-ebpf
BUILD_SCRIPTS_DIRECTORY=scripts/build
BPF_CLANG := clang-14
INCLUDE_C_FLAGS := -I/tmp/caretta_extra/libbpf_headers -I/tmp/${PROJECT_DIRNAME}/
BPF_CFLAGS := -O2 -g -Wall -Werror -fdebug-prefix-map=/ebpf=. ${INCLUDE_C_FLAGS}
IMAGE=quay.io/cilium/ebpf-builder
VERSION=1648566014

ARCH=amd64 # amd64 or arm64

.PHONY: build
build: ${BIN_DIR} pkg/tracing/bpf_bpfel_x86.go cmd/caretta/caretta.go
	GOOS=linux GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -o ${BINARY_PATH} cmd/caretta/caretta.go

${BIN_DIR}:
	mkdir -p ${BIN_DIR}

.PHONY: download_libbpf_headers
download_libbpf_headers: 
	${REPODIR}/${BUILD_SCRIPTS_DIRECTORY}/download_libbpf_headers.sh

.PHONY: generate_ebpf
generate_ebpf: ${BPF2GO_BINARY}_${BPF2GO_VERSION} \
				download_libbpf_headers
	go mod vendor
	(cd ${REPODIR}/pkg/tracing && \
		GOPACKAGE=tracing ${REPODIR}/${BPF2GO_BINARY}_${BPF2GO_VERSION} \
		-cc "${BPF_CLANG}" -cflags "${BPF_CFLAGS}"  \
		-target arm64,amd64 bpf \
		ebpf/caretta.bpf.c --)

${BPF2GO_BINARY}_${BPF2GO_VERSION}:
	git clone -q --branch v${BPF2GO_VERSION} https://github.com/cilium/ebpf \
		${CILIUM_EBPF_DIRECTORY} 2>/dev/null
	cd ${CILIUM_EBPF_DIRECTORY} && \
		go build -o ${REPODIR}/${BPF2GO_BINARY}_${BPF2GO_VERSION} ./cmd/bpf2go

.PHONY: generate_ebpf_in_docker
generate_ebpf_in_docker: ${BIN_DIR}
	${DOCKER_BIN} run \
		-v ${REPODIR}:/tmp/caretta \
		-w /tmp/${PROJECT_DIRNAME} \
		--env HOME="/tmp/" \
		"${IMAGE}:${VERSION}" \
		${MAKE} generate_ebpf

pkg/tracing/bpf_bpfel%.go: pkg/tracing/ebpf/caretta.bpf.c
	$(MAKE) generate_ebpf

# -----------------------

VMNAMES := gijs1 gijs2 gijs3

VM_gijs1_HOST = 35.156.26.48
VM_gijs1_USER = ubuntu
VM_gijs1_KEY  = ~/.ssh/gijs1.pem

VM_gijs2_HOST = 35.159.165.52
VM_gijs2_USER = ubuntu
VM_gijs2_KEY  = ~/.ssh/gijs1.pem

VM_gijs3_HOST = 3.127.217.236
VM_gijs3_USER = ubuntu
VM_gijs3_KEY  = ~/.ssh/gijs1.pem

ssh-%:
	@echo "SSH into VM '$*'..."
	ssh -o ServerAliveInterval=60 -i $(VM_$*_KEY) $(VM_$*_USER)@$(VM_$*_HOST) "$(CMD)"

fetch-%:
	@echo "Fetching file from VM '$*' to host..."
	scp -i $(VM_$*_KEY) $(VM_$*_USER)@$(VM_$*_HOST):/home/ubuntu/caretta/bin/* ~/Development/uu/thesis/caretta/bin/


build-for-docker:
	@$(MAKE) ssh-gijs2 CMD="cd ~/caretta && git pull && make build && exit"; \
	$(MAKE) fetch-gijs2; \
	docker build -t host.docker.internal:5000/caretta:latest -f Dockerfile . --platform linux/amd64; \
	docker push host.docker.internal:5000/caretta:latest