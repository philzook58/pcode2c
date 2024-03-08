from javax.swing.text import StyleConstants, SimpleAttributeSet
import java.awt

import re

types = r"u?int\d+_t|char|int|double|float|void|size_t|ssize_t|off_t|pid_t|uid_t|gid_t|boolean"
keywords = r"if|else|switch|case|default|while|do|for|break|continue|return|goto|typedef|struct|union|enum|register|static|auto|extern|const|volatile|restrict"


def C_syntax_highlight(doc):
    comment = SimpleAttributeSet()
    StyleConstants.setForeground(comment, java.awt.Color(0, 128, 0))
    keyword = SimpleAttributeSet()
    StyleConstants.setForeground(keyword, java.awt.Color(128, 0, 0))
    type_ = SimpleAttributeSet()
    StyleConstants.setForeground(type_, java.awt.Color(0, 0, 255))
    l = doc.getText(0, doc.getLength())
    for m in re.finditer(types, l):
        doc.setCharacterAttributes(m.start(), m.end() - m.start(), type_, False)
    for m in re.finditer(keywords, l):
        doc.setCharacterAttributes(m.start(), m.end() - m.start(), keyword, False)
    startIndex = 0
    for line in l.split("\n"):
        line_index = line.find("//")
        if line_index != -1:
            doc.setCharacterAttributes(
                startIndex + line_index, len(line) - line_index, comment, False
            )
        line_index = line.find("#include")
        if line_index != -1:
            doc.setCharacterAttributes(
                startIndex + line_index, len(line) - line_index, keyword, False
            )
        startIndex += len(line) + 1
