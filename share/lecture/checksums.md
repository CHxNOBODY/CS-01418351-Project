# Why every transfer carries a SHA-256

TCP's checksum is 16 bits and covers accidental corruption only.
It says nothing about a file that was truncated by a crash, or
altered on the disk it came from. A SHA-256 over the payload closes
both gaps, and costs one pass over data we are reading anyway.
