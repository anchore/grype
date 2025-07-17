TOOL_DIR = .tool
BINNY = $(TOOL_DIR)/binny
TASK = $(TOOL_DIR)/task

.DEFAULT_GOAL := make-default

## Bootstrapping targets #################################

# note: we need to assume that binny and task have not already been installed
$(BINNY):
	@mkdir -p $(TOOL_DIR)
	@curl -sSfL https://raw.githubusercontent.com/anchore/binny/main/install.sh | sh -s -- -b $(TOOL_DIR)

# note: we need to assume that binny and task have not already been installed
.PHONY: task
$(TASK) task: $(BINNY)
	@$(BINNY) install task -q

.PHONY: ci-bootstrap-go
ci-bootstrap-go:
	go mod download

# this is a bootstrapping catch-all, where if the target doesn't exist, we'll ensure the tools are installed and then try again
%:
	make $(TASK)
	$(TASK) $@

## Shim targets #################################

.PHONY: make-default
make-default: $(TASK)
	@# run the default task in the taskfile
	@$(TASK)

# for those of us that can't seem to kick the habit of typing `make ...` lets wrap the superior `task` tool
TASKS := $(shell bash -c "test -f $(TASK) && $(TASK) -l | grep '^\* ' | cut -d' ' -f2 | tr -d ':' | tr '\n' ' '" ) $(shell bash -c "test -f $(TASK) && $(TASK) -l | grep 'aliases:' | cut -d ':' -f 3 | tr '\n' ' ' | tr -d ','")

.PHONY: $(TASKS)
$(TASKS): $(TASK)
	@$(TASK) $@

help: $(TASK)
	@$(TASK) -l
