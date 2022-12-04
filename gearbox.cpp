#include "gearbox.hpp"
#include "crsUtils.hpp"

#include <chrono>
#include <thread>


#define P1_RPM_UPSHIFT          0.325
#define P1_ACCEL_UPSHIFT        0
#define P2_RPM_UPSHIFT          0.4
#define P2_ACCEL_UPSHIFT        40
#define P3_RPM_UPSHIFT          0.75
#define P3_ACCEL_UPSHIFT        90
#define P4_RPM_UPSHIFT          0.875
#define P4_ACCEL_UPSHIFT        100

#define P1_RPM_DOWNSHIFT        0.20
#define P1_ACCEL_DOWNSHIFT      0
#define P2_RPM_DOWNSHIFT        0.25
#define P2_ACCEL_DOWNSHIFT      50
#define P3_RPM_DOWNSHIFT        0.45
#define P3_ACCEL_DOWNSHIFT      90
#define P4_RPM_DOWNSHIFT        0.5
#define P4_ACCEL_DOWNSHIFT      100

#define TIME_DECELERATION_MS    3000
#define TIME_BETWEEN_SHIFT_MS   80

#define MAX_GEAR                9

void updateGearbox(forza::ForzaPackets &packets)
{
  /// USER CODE BEGIN ///
  if(packets.data["is_race_on"]) {
    int upshift = 0;
    int downshift = 0;

    float max_rpm = static_cast<float>(packets.data["engine_max_rpm"]);

    float x = static_cast<float>(packets.data["current_engine_rpm"]);
    float y = static_cast<float>(packets.data["accel"]) / 255.f * 100.f;

    upshift += crossProduct(x, y, P1_RPM_UPSHIFT * max_rpm, P1_ACCEL_UPSHIFT, P2_RPM_UPSHIFT * max_rpm, P2_ACCEL_UPSHIFT) > 0.f ? 1 : -1;
    upshift += crossProduct(x, y, P2_RPM_UPSHIFT * max_rpm, P2_ACCEL_UPSHIFT, P3_RPM_UPSHIFT * max_rpm, P3_ACCEL_UPSHIFT) > 0.f ? 1 : -1;
    upshift += crossProduct(x, y, P3_RPM_UPSHIFT * max_rpm, P3_ACCEL_UPSHIFT, P4_RPM_UPSHIFT * max_rpm, P4_ACCEL_UPSHIFT) > 0.f ? 1 : -1;

    downshift += crossProduct(x, y, P1_RPM_DOWNSHIFT * max_rpm, P1_ACCEL_DOWNSHIFT, P2_RPM_DOWNSHIFT * max_rpm, P2_ACCEL_DOWNSHIFT) > 0.f ? 1 : -1;
    downshift += crossProduct(x, y, P2_RPM_DOWNSHIFT * max_rpm, P2_ACCEL_DOWNSHIFT, P3_RPM_DOWNSHIFT * max_rpm, P3_ACCEL_DOWNSHIFT) > 0.f ? 1 : -1;
    downshift += crossProduct(x, y, P3_RPM_DOWNSHIFT * max_rpm, P3_ACCEL_DOWNSHIFT, P4_RPM_DOWNSHIFT * max_rpm, P4_ACCEL_DOWNSHIFT) > 0.f ? 1 : -1;

    // BEHAVIOUR
    static auto t_deceleration = std::chrono::high_resolution_clock::now();
    static auto t_shift = std::chrono::high_resolution_clock::now();

    if(y > 40) {
      t_deceleration = std::chrono::high_resolution_clock::now();
    }

    if(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t_shift).count() > TIME_BETWEEN_SHIFT_MS) {
      if( upshift > 1 &&
          packets.data["gear"] < MAX_GEAR &&
          (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t_deceleration).count() > TIME_DECELERATION_MS || y > 40)) {
        //shift up
        crs::keyboardPress('e');
        t_shift = std::chrono::high_resolution_clock::now();
      }
      if( downshift <= 1 &&
          packets.data["gear"] > 1) {
        //shift down
        crs::keyboardPress('d');
        t_shift = std::chrono::high_resolution_clock::now();
      }
    }
  }
  /// USER CODE END ///
}