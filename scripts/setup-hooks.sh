#!/bin/bash
# Senior DevSecOps Engineer's Auto-Hook Script

echo "🔧 Setting up Git Hooks..."
# This ensures gitleaks runs on every commit
git config core.hooksPath .githooks

echo "✅ Hooks path updated. Shifting Left is now active."