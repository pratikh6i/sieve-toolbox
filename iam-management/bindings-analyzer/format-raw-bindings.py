import re

def process_text_file(filepath):
    """
    Reads a text file, applies specific replacements, and returns the modified text.

    Args:
        filepath: The path to the text file.

    Returns:
        The processed text as a string, or None if the file is not found.
    """
    try:
        with open(filepath, 'r') as f:
            text = f.read()

        text = text.replace('"[{', '[{')
        text = text.replace('}]"', '}],')
        # text = "[" + text + "]"
        text = re.sub(r",\s*]", "]", text)  # Use raw string for regex
        return text

    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None


if __name__ == "__main__":
    filepath = "/home/pratik_shetti/NTUC/IAM-processor/iam-raw.txt"  # Replace with your file path if different
    processed_text = process_text_file(filepath)

    if processed_text:
        print(processed_text)

        # To save the processed text to a new file (optional):
        # with open("iam-processed.txt", "w") as outfile:
        #     outfile.write(processed_text)