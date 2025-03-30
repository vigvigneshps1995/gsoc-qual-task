SCRIPTS = scripts

PYTHON2_OK := $(shell python2 --version 2>&1)
PYTHON3_OK := $(shell python3 --version 2>&1)
ifeq ('$(PYTHON2_OK)','')
	ifeq ('$(PYTHON3_OK)','')
		$(error package 'python 2 or 3' not found)
	else
		PYTHON = python3
	endif
else
	PYTHON = python2
endif


export MN_STRATUM_IMG = opennetworking/mn-stratum
export P4RUNTIME_SH_IMG = p4lang/p4runtime-sh:latest

# export P4_PROGRAM_DIRNAME ?=
# export P4_PROGRAM_NAME ?=
# export P4RT_PROGRAM_DIRNAME ?=
# export P4RT_PROGRAM_NAME ?=
export P4_PROGRAM_DIRNAME ?=
export P4_PROGRAM_NAME ?=
export P4RT_PROGRAM_DIRNAME ?=
export P4RT_PROGRAM_NAME ?=

export topo ?= linear,2 
export name ?=
export grpc_port ?= 50001

mininet: 
	$(SCRIPTS)/mn-stratum --topo $(topo)

mininet-prereqs:
	docker exec -it mn-stratum bash -c \
		"echo 'deb http://archive.debian.org/debian buster main contrib non-free' > /etc/apt/sources.list && \
		 echo 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99no-check-valid && \
		 echo 'Acquire::AllowInsecureRepositories \"true\";' >> /etc/apt/apt.conf.d/99no-check-valid && \
		 apt-get update && \
		 apt-get -y --allow-unauthenticated install iproute2 python3-scapy"


# Usage: make controller name=bridge grpc_port=50001 topo=linear,2,2
controller:
	make .controller-$(name)

# Usage: make controller-logs name=decision-tree grpc_port=50001
controller-logs:
	make .controller-$(name)-logs

# Usage: make host name=h1s1
# host:
# 	chmod +x $(SCRIPTS)/utils/mn-stratum/exec
# 	$(SCRIPTS)/utils/mn-stratum/exec $(name)

host:
	$(SCRIPTS)/utils/mn-stratum/exec $(name)


clean: .p4rt-clean .p4-clean

####################################################################
# Controller Types
####################################################################
.controller-decision-tree:
	P4_PROGRAM_NAME=decision_tree \
	P4RT_PROGRAM_NAME=decision_tree \
	make .p4rt-script
####################################################################
# P4 Runtime 
####################################################################
.p4rt-script-dt: .p4-build
	mkdir -p logs/$(P4_PROGRAM_DIRNAME)
	chmod +x $(SCRIPTS)/p4runtime-sh.run-script
	P4RUNTIME_SH_DOCKER_NAME=p4runtime-sh-$(grpc_port) \
	$(SCRIPTS)/p4runtime-sh.run-script \
		"p4rt-src/$(P4RT_PROGRAM_DIRNAME)/$(P4RT_PROGRAM_NAME).py \
		--p4info=cfg/$(P4_PROGRAM_DIRNAME)/$(P4_PROGRAM_NAME)-$(grpc_port)-p4info.txt \
		--bmv2-json=cfg/$(P4_PROGRAM_DIRNAME)/$(P4_PROGRAM_NAME)-$(grpc_port).json"

.p4rt-script: .p4-build
	mkdir -p logs/$(P4_PROGRAM_DIRNAME)
	chmod +x $(SCRIPTS)/p4runtime-sh.run-script
	P4RUNTIME_SH_DOCKER_NAME=p4runtime-sh-$(grpc_port) \
	$(SCRIPTS)/p4runtime-sh.run-script \
		"p4rt-src/$(P4RT_PROGRAM_DIRNAME)/$(P4RT_PROGRAM_NAME).py --grpc-port=$(grpc_port) --topo-config=topo/$(topo).json"

.p4rt-logs:
	cat logs/$(P4_PROGRAM_DIRNAME)/$(P4_PROGRAM_NAME)-$(grpc_port)-table.json

.p4rt-clean:
	rm -rf logs

####################################################################
# Build P4
####################################################################

.p4-build:
	mkdir -p cfg/$(P4_PROGRAM_DIRNAME)
	chmod +x $(SCRIPTS)/p4c
	$(SCRIPTS)/p4c p4c-bm2-ss --arch v1model \
		-o cfg/$(P4_PROGRAM_DIRNAME)/$(P4_PROGRAM_NAME)-$(grpc_port).json \
		-DTARGET_BMV2 -DCPU_PORT=255 \
		--p4runtime-files cfg/$(P4_PROGRAM_DIRNAME)/$(P4_PROGRAM_NAME)-$(grpc_port)-p4info.txt \
		p4-src/$(P4_PROGRAM_DIRNAME)/$(P4_PROGRAM_NAME).p4

.p4-build-tutorials:
	chmod +x $(SCRIPTS)/p4c
	$(SCRIPTS)/p4c p4c-bm2-ss --arch v1model \
		-o $(P4_PROGRAM_DIRNAME)/build/$(P4_PROGRAM_NAME)-$(grpc_port).json \
		-DTARGET_BMV2 -DCPU_PORT=255 \
		--p4runtime-files $(P4_PROGRAM_DIRNAME)/build/$(P4_PROGRAM_NAME)-$(grpc_port)-p4info.txt \
		$(P4_PROGRAM_DIRNAME)/$(P4_PROGRAM_NAME).p4
	
.p4-build-decision-tree:
	mkdir -p cfg/decision_tree
	chmod +x scripts/p4c
	scripts/p4c p4c-bm2-ss --arch v1model \
		-o cfg/decision_tree-$(grpc_port).json \
		-DTARGET_BMV2 -DCPU_PORT=255 \
		--p4runtime-files cfg/decision_tree-$(grpc_port)-p4info.txt \
		p4-src/decision_tree.p4

.p4-clean:
	rm -rf cfg

