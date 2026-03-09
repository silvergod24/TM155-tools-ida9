This project uses one prompt in order to create a new processor module 
in IDAPython, for IDA9.3

## How This Works

Instead of forcing an AI to read a 500-page PDF datasheet and guess how to write a decompiler, this prompt enforces a strict three-phase pipeline:

1. **The Shortcut Phase:** The AI is instructed to first search for existing, open-source machine-readable definitions of your target architecture (like Ghidra SLEIGH files or GNU Binutils C source code). These are much more accurate than parsing PDFs.
2. **The Extraction Phase (Fallback):** If shortcuts don't exist, the AI will write a targeted Python script using visual/tabular extraction libraries (like `camelot-py` or `tabula-py`) to rip the exact instruction bitmasks and register definitions out of your datasheet. 
3. **The Generation Phase:** The AI takes the precise architecture data and wraps it in a modern, IDA 9.3-compliant `processor_t` class template, utilizing modern `ida_typeinf`, modern segment creation, and strict `try/except` diagnostic rendering blocks.

## How to Use the Prompt

1. Grab the **Prompt** text.
2. Fill in the `[INSERT ARCHITECTURE NAME HERE]` bracket.
3. Provide the AI with the architecture data (if the shortcut doesn't work). You can do this by:
   * Attaching the official PDF datasheet.
   * Pasting a link to the datasheet.
4. Provide the AI with a **Reference Template**. (Use a working, modern IDA 9.3 Python script, like the Holtek HT68FB560 script, so the AI knows exactly how to structure its classes and loops).
5. Submit the prompt to the AI. 

## Integrating the Generated Module into IDA Pro

The AI will output two primary files: an `[architecture].py` file and an `[architecture].json` file. Here is how to load them:

### 1. Place the Files
Copy both the `.py` and `.json` files into your IDA Pro user `procs` directory. Do not place them in the main IDA installation folder; use your user-specific application data folder:
* **Windows:** `%APPDATA%\Hex-Rays\IDA Pro\procs\`
* **Linux / macOS:** `~/.idapro/procs/`

*(Note: If the `procs` folder does not exist, simply create it).*

### 2. Test the Module
1. Launch IDA Pro 9.3.
2. Drag and drop your raw firmware `.bin` or `.rom` file into the IDA window.
3. In the "Load a new file" dialog, look at the **Processor type** dropdown menu.
4. Select your newly generated processor from the list.
5. Click **OK**.

### 3. Troubleshooting
Because the Master Prompt forces the AI to wrap its rendering callbacks (`notify_out_insn` and `notify_out_operand`) in `try/except` blocks, **IDA will not silently fail.** If the AI hallucinates a bad instruction mask or makes a deprecated API call, look at the **Output Window** at the bottom of the IDA interface. It will print a bright red Python traceback detailing exactly which line failed. You can simply copy that error, paste it back to the AI, and say: *"Fix this specific error adhering to the IDA 9.3 API rules."*