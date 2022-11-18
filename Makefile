.PHONY: all clean

DRAFT=userinfo-vc

all: ${DRAFT}.html

${DRAFT}.xml: ${DRAFT}.md
	mmark ${DRAFT}.md >${DRAFT}.xml

${DRAFT}.html: ${DRAFT}.xml
	xml2rfc --html ${DRAFT}.xml

clean:
	rm -f ${DRAFT}.xml
	rm -f ${DRAFT}.html
