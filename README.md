# frtpm
A simple RTP-MIDI to ALSA gateway/pipe/bridge.
Run it somewhere and it can bidirectionally bridge MIDI from/to ALSA to/from RTP-MIDI.


# how to build
* mkdir build
* cd build
* cmake ..
* make


# how to run
Just start it. It listens hardcoded on port 5004/5005 altough you can override 5004 using '-b' (5005 will be the next port).


# see also
* https://github.com/davidmoreno/rtpmidid more advanced version of the same thing


(c) 2021 by Folkert van Heusden <mail@vanheusden.com>
license: BSD 3-Clause
