#ifndef GEARBOX_HPP
#define GEARBOX_HPP

#include <windows.h>
#include "packets.hpp"


inline bool enableGearbox = true;

void updateGearbox(forza::ForzaPackets &packets);

inline float
crossProduct(float x, float y, float x1, float y1, float x2, float y2) { return (x-x1)*(y2-y1)-(y-y1)*(x2-x1); }

#endif GEARBOX_HPP