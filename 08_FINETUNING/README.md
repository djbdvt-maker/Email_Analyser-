# HopZero AI Fine-Tuning Pipeline

This directory contains everything you need to fine-tune your own version of Llama-3-8B specifically on the HopZero forensic schemas to massively improve precision and speed when running locally on Ollama.

## 1. Generate the Dataset
Run the `dataset_generator.py` script. It parses all the raw `.eml` test emails from your `07_TEST_DATA` folder and maps them against the rules defined in their respective `manifest.json` files to automatically generate a `train.jsonl` file in ShareGPT format.

```bash
python dataset_generator.py
```
*(A `train.jsonl` file has already been generated for you with 5 examples!)*

## 2. Train on Google Colab
Since you are using a laptop, Google Colab is the easiest way to train (the free T4 GPU works perfectly).
1. Go to [Google Colab](https://colab.research.google.com/).
2. Click **File -> Upload notebook** and upload `HopZero_FineTuning_Colab.ipynb`.
3. In Colab, click the folder icon on the left panel, and upload your generated `train.jsonl` file.
4. Click **Runtime -> Run all**.
5. The notebook uses Unsloth and QLoRA to fine-tune Llama 3 8B in 4-bit memory. When it finishes, it will export a `.gguf` file to your Colab instance. Download this file to your laptop.

## 3. Serve with Ollama
Once you have downloaded the fine-tuned `.gguf` file (e.g. `hopzero_model-unsloth.Q4_K_M.gguf`), move it into this directory alongside the `Modelfile`.

Run the following command to import your custom model into Ollama:
```bash
ollama create hopzero-llama -f Modelfile
```

Then, configure your `03_BACKEND` `.env` file to use it:
```env
HOPZERO_LLM_PROVIDER=ollama
HOPZERO_LLM_MODEL=hopzero-llama
```
