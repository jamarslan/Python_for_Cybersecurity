# word to pdf converter
from docx import Document
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import os

def word_to_pdf(word_path, pdf_path):
	doc = Document(word_path)
	# create path
	c = canvas.Canvas(pdf_path, pagesize=A4)
	width,height = A4
	y = height - 50
	for para in doc.paragraphs:
		text = para.text.strip()
		if text:
			c.drawString(50,y,text)
			y -= 15
			if y < 50:
				c.showPage()
				y = height - 50
	c.save()
	print(f"Converted {word_path} to {pdf_path}")
if __name__ == "__main__":
	word_file = input("Enter the path to word (.docx) file: ").strip()
	if not os.path.exists(word_file):
		print("[!] File not found. ")
	elif not word_file.lower().endswith(".docx"):
		print("[!] Only .docx files are supported.")
	else:
		pdf_file = os.path.splitext(word_file)[0] + ".pdf"
		word_to_pdf(word_file, pdf_file)
