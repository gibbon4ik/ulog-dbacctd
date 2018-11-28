all: ulog-acctd.info ulog-acctd.html

ulog-acctd.dvi: ulog-acctd.texi
	texi2dvi ulog-acctd.texi

ulog-acctd.info: ulog-acctd.texi
	makeinfo ulog-acctd.texi

ulog-acctd.html:
	makeinfo --no-split --html ulog-acctd.texi

clean:
	rm -f *.dvi *.info *.xml *.html \
		*.aux *.cp *.cps *.fn *.ky *.log *.pg *.toc *.tp *.vr

