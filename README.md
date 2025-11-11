


## DATA set 다운로드 
```
# Make sure the hf CLI is installed
powershell -ExecutionPolicy ByPass -c "irm https://hf.co/cli/install.ps1 | iex"

# Download the dataset
hf download qualifire/prompt-injections-benchmark --repo-type=dataset
```