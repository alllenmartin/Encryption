from pypdf import PdfReader, PdfWriter

reader = PdfReader("document.pdf")

writer = PdfWriter()
writer.append_pages_from_reader(reader)
writer.encrypt("password")

with open("output.pdf", "wb") as out_file:
    writer.write(out_file)