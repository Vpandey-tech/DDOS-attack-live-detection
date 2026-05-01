import PyPDF2
try:
    with open("final black book.pdf", "rb") as f:
        reader = PyPDF2.PdfReader(f)
        for i, page in enumerate(reader.pages):
            text = page.extract_text()
            if text and ("test case" in text.lower() or "test cases" in text.lower()):
                print(f"--- Page {i+1} ---")
                print(text[:1000])  # print first 1000 characters of the page to find format
except Exception as e:
    print(f"Error reading with PyPDF2: {e}")
