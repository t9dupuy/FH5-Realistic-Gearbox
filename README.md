# FH5 Realistic Automatic Gearbox

This mod is an alternative to FH5's very basic automatic transmission. This new realistic automatic transmission was made to replicate real world modern car gearbox behaviour.

## Setup

**In the game** : go to *Settings > HUD* and turn "Data Out" on, set IP address to "127.0.0.1" and port to "1123" 

[Download](https://github.com/t9dupuy/FH5-Realistic-Gearbox/releases/tag/v0.1-alpha) and lauch the executable.

## How does it work ?

The mod uses a feature of the game called "Data Out" which sends real-time data about the game over UDP. 
The data is received and analysed by the mod that then emulates keyboard pressed to shift up or down.

### Logic

The logic behind the behaviour of this alternative gearbox is pretty simple.
Every time a new data packet is received (60 times a second), a point is generated on the following graph. The position of this new point is used as follows:
* If the point is left to the red line, the software tries to shift down
* If the point is right to the blue line, the software tries to shift up
* If the point is between the two lines, the software does nothing

![graph](https://user-images.githubusercontent.com/74502713/205510725-e0435a69-cf65-49df-9e36-e40dccc452c9.png)
