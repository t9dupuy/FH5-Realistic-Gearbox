#include <thread>
#include <mutex>
#include <chrono>
#include <iostream>

#include "crsUtils.hpp"
#include "packets.hpp"
#include "gearbox.hpp"

#define REFRESH_RATE      20     //optimal refresh rate in hertz

/// USER GLOBAL VARIABLES BEGIN ///
char tmpRequest[512];               //data receive buffer
forza::ForzaPackets packets;        //data convert class
std::mutex m;                       //data lock mutex
/// USER GLOBAL VARIABLES END ///

void receive_convert_data()
{
  //---- create UDP socket ----
  SOCKET udpSocket=crs::socket(PF_INET, SOCK_DGRAM, 0);
  // ... bound to the specified port
  crs::bind(udpSocket, 9988);

  for(;;)
  {
    auto [r, fromIpAddr, fromPort] = crs::recvfrom(udpSocket, &tmpRequest, sizeof(tmpRequest));

    m.lock();
    packets.write_to_data(tmpRequest);
    m.unlock();
  }
}

void keyListen()
{
  for(;;)
  {
    if(GetKeyState('U') & 0x8000)
    {
      enableGearbox = !enableGearbox;
      if(enableGearbox)
      {
        std::cout << "Manual mode is now enabled\n";
      } else
      {
        std::cout << "Manual mode is now disabled\n";
      }
      while(GetKeyState('U') & 0x8000);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

void mainLoop()
{
  for(;;)
  {
    /// TIMING CODE BEGIN ///
    auto t0 = std::chrono::high_resolution_clock::now();
    /// TIMING CODE END ///

    m.lock();
      updateGearbox(packets);
    m.unlock();

    /// TIMING CODE BEGIN ///
    auto t1 = std::chrono::high_resolution_clock::now();
    auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0);
    if((1000/REFRESH_RATE) < delta.count()) {
      std::cout << "REFRESH_RATE is too high : can't keep up!\n";
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(1000/REFRESH_RATE) - delta);
    }
    /// TIMING CODE END ///
  }
}

int main()
{
  std::thread udp_server(receive_convert_data);
  udp_server.detach();

  std::thread keyListener(keyListen);
  keyListener.detach();

  crs::keyboardInit();

  std::cout << "Close this window when you are done using the mod!\n\n";
  std::cout << "Press U to switch between automatic and manual mode\n";
  mainLoop();

  return 0;
}