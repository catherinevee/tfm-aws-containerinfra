# ==============================================================================
# AWS Container Infrastructure Terraform Module Makefile
# ==============================================================================

.PHONY: help init plan apply destroy validate fmt lint test clean examples

# Default target
help:
	@echo "AWS Container Infrastructure Terraform Module"
	@echo ""
	@echo "Available targets:"
	@echo "  init      - Initialize Terraform"
	@echo "  plan      - Plan Terraform changes"
	@echo "  apply     - Apply Terraform changes"
	@echo "  destroy   - Destroy Terraform resources"
	@echo "  validate  - Validate Terraform configuration"
	@echo "  fmt       - Format Terraform code"
	@echo "  lint      - Lint Terraform code"
	@echo "  test      - Run tests"
	@echo "  clean     - Clean up temporary files"
	@echo "  examples  - Run examples"
	@echo "  docs      - Generate documentation"

# ==============================================================================
# Terraform Operations
# ==============================================================================

init:
	@echo "Initializing Terraform..."
	terraform init

plan:
	@echo "Planning Terraform changes..."
	terraform plan

apply:
	@echo "Applying Terraform changes..."
	terraform apply

destroy:
	@echo "Destroying Terraform resources..."
	terraform destroy

# ==============================================================================
# Code Quality
# ==============================================================================

validate:
	@echo "Validating Terraform configuration..."
	terraform validate

fmt:
	@echo "Formatting Terraform code..."
	terraform fmt -recursive

lint:
	@echo "Linting Terraform code..."
	@if command -v tflint >/dev/null 2>&1; then \
		tflint --init; \
		tflint; \
	else \
		echo "tflint not found. Install with: go install github.com/terraform-linters/tflint/cmd/tflint@latest"; \
	fi

# ==============================================================================
# Testing
# ==============================================================================

test: validate fmt lint
	@echo "Running tests..."
	@if [ -d "test" ]; then \
		cd test && terraform init && terraform plan; \
	else \
		echo "No test directory found"; \
	fi

# ==============================================================================
# Examples
# ==============================================================================

examples:
	@echo "Running examples..."
	@for example in examples/*/; do \
		if [ -d "$$example" ]; then \
			echo "Testing example: $$example"; \
			cd "$$example" && terraform init && terraform plan -out=tfplan && rm tfplan; \
			cd ../..; \
		fi; \
	done

# ==============================================================================
# Documentation
# ==============================================================================

docs:
	@echo "Generating documentation..."
	@if command -v terraform-docs >/dev/null 2>&1; then \
		terraform-docs markdown table . > README.md.tmp; \
		mv README.md.tmp README.md; \
	else \
		echo "terraform-docs not found. Install with: go install github.com/terraform-docs/terraform-docs/cmd/terraform-docs@latest"; \
	fi

# ==============================================================================
# Cleanup
# ==============================================================================

clean:
	@echo "Cleaning up temporary files..."
	find . -name "*.tfstate*" -delete
	find . -name "*.tfplan" -delete
	find . -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name ".terraform.lock.hcl" -delete

# ==============================================================================
# Development
# ==============================================================================

dev-setup:
	@echo "Setting up development environment..."
	@if ! command -v terraform >/dev/null 2>&1; then \
		echo "Terraform not found. Please install Terraform first."; \
		exit 1; \
	fi
	@if ! command -v aws >/dev/null 2>&1; then \
		echo "AWS CLI not found. Please install AWS CLI first."; \
		exit 1; \
	fi
	@if ! command -v kubectl >/dev/null 2>&1; then \
		echo "kubectl not found. Please install kubectl first."; \
		exit 1; \
	fi
	@echo "Development environment setup complete!"

# ==============================================================================
# Security
# ==============================================================================

security-scan:
	@echo "Running security scan..."
	@if command -v terrascan >/dev/null 2>&1; then \
		terrascan scan -i terraform .; \
	else \
		echo "terrascan not found. Install with: go install github.com/tenable/terrascan/cmd/terrascan@latest"; \
	fi

# ==============================================================================
# Cost Estimation
# ==============================================================================

cost-estimate:
	@echo "Estimating costs..."
	@if command -v infracost >/dev/null 2>&1; then \
		infracost breakdown --path .; \
	else \
		echo "infracost not found. Install with: brew install infracost"; \
	fi

# ==============================================================================
# Pre-commit
# ==============================================================================

pre-commit: fmt lint validate
	@echo "Pre-commit checks completed successfully!"

# ==============================================================================
# Release
# ==============================================================================

release:
	@echo "Creating release..."
	@if [ -z "$(VERSION)" ]; then \
		echo "Please specify VERSION=1.0.0"; \
		exit 1; \
	fi
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)

# ==============================================================================
# Module Registry
# ==============================================================================

publish:
	@echo "Publishing module to Terraform Registry..."
	@echo "This is a placeholder. Implement your publishing logic here."
	@echo "Consider using GitHub Actions for automated publishing."

# ==============================================================================
# Monitoring
# ==============================================================================

monitor:
	@echo "Setting up monitoring..."
	@echo "This is a placeholder. Implement your monitoring setup here."

# ==============================================================================
# Backup
# ==============================================================================

backup:
	@echo "Creating backup..."
	@echo "This is a placeholder. Implement your backup logic here."

# ==============================================================================
# Disaster Recovery
# ==============================================================================

dr-test:
	@echo "Testing disaster recovery..."
	@echo "This is a placeholder. Implement your DR testing logic here."

# ==============================================================================
# Compliance
# ==============================================================================

compliance-check:
	@echo "Running compliance checks..."
	@echo "This is a placeholder. Implement your compliance checks here."

# ==============================================================================
# Performance
# ==============================================================================

performance-test:
	@echo "Running performance tests..."
	@echo "This is a placeholder. Implement your performance tests here."

# ==============================================================================
# All-in-one
# ==============================================================================

all: dev-setup init validate fmt lint test examples security-scan cost-estimate
	@echo "All checks completed successfully!"

# ==============================================================================
# Helpers
# ==============================================================================

version:
	@echo "Terraform version:"
	terraform version
	@echo ""
	@echo "AWS CLI version:"
	aws --version
	@echo ""
	@echo "kubectl version:"
	kubectl version --client

status:
	@echo "Checking Terraform status..."
	terraform show

outputs:
	@echo "Terraform outputs:"
	terraform output

# ==============================================================================
# Troubleshooting
# ==============================================================================

debug:
	@echo "Debug information:"
	@echo "Terraform version: $(shell terraform version)"
	@echo "AWS region: $(shell aws configure get region)"
	@echo "AWS account: $(shell aws sts get-caller-identity --query Account --output text)"
	@echo "Current directory: $(PWD)"
	@echo "Terraform files:"
	@find . -name "*.tf" -type f

# ==============================================================================
# Environment-specific
# ==============================================================================

dev: environment=dev
dev: apply

staging: environment=staging
staging: apply

prod: environment=prod
prod: apply

# ==============================================================================
# End of Makefile
# ============================================================================== 