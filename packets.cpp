#include "packets.hpp"
#include <algorithm>
#include <iterator>

namespace forza {
    
    ForzaPackets::ForzaPackets() {};

    void ForzaPackets::write_to_data(char* buf_begin) {
        char patched_data[311];
        memcpy(patched_data, buf_begin, 232 * sizeof(char));
        memcpy(patched_data + 232, buf_begin + 244, 79 * sizeof(char));

        size_t advancement = 0;
        
        for (int i = 1; i < 86; i++)
        {
            if (this->format[i] == 'i') {
                char new_buf[4];
                memcpy(new_buf, &patched_data[0] + advancement, 4 * sizeof(char));
                this->data[this->props[i - 1]] = (float)(*(int*)&new_buf);
                advancement += 4;
            }
            else if (this->format[i] == 'I') {
                char new_buf[4];
                memcpy(new_buf, &patched_data[0] + advancement, 4 * sizeof(char));
                this->data[this->props[i - 1]] = (float)(*(unsigned int*)&new_buf);
                advancement += 4;
            }
            else if (this->format[i] == 'f') {
                char new_buf[4];
                memcpy(new_buf, &patched_data[0] + advancement, 4 * sizeof(char));
                this->data[this->props[i - 1]] = (float)(*(float*)&new_buf);
                advancement += 4;
            }
            else if (this->format[i] == 'H') {
                char new_buf[2];
                memcpy(new_buf, &patched_data[0] + advancement, 2 * sizeof(char));
                this->data[this->props[i - 1]] = (float)(*(unsigned short*)&new_buf);
                advancement += 2;
            }
            else if (this->format[i] == 'B') {
                char new_buf[1];
                memcpy(new_buf, &patched_data[0] + advancement, 1 * sizeof(char));
                this->data[this->props[i - 1]] = (float)(*(unsigned char*)&new_buf);
                advancement += 1;
            }
            else if (this->format[i] == 'b') {
                char new_buf[1];
                memcpy(new_buf, &patched_data[0] + advancement, 1 * sizeof(char));
                this->data[this->props[i - 1]] = (float)(*(char*)&new_buf);
                advancement += 1;
            }
        }

        
    };

} //namespace forza