#include "myFIFO.h"
#include <cassert>

myFIFO::myFIFO(CACHE* cache) : myFIFO(cache, cache->NUM_SET, cache->NUM_WAY) {}

myFIFO::myFIFO(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways) {
    cycle_array_size = (size_t)(sets * ways);
    arrival_cycles = new uint64_t[cycle_array_size];
    for (size_t i = 0; i < cycle_array_size; i++) {
        arrival_cycles[i] = 0;
    }
}

myFIFO::~myFIFO() {
    delete[] arrival_cycles;
}

myFIFO::myFIFO(const myFIFO& other)
    : replacement(other), NUM_WAY(other.NUM_WAY), cycle_array_size(other.cycle_array_size), cycle(other.cycle)
{
    arrival_cycles = new uint64_t[cycle_array_size];
    for (size_t i = 0; i < cycle_array_size; i++) {
        arrival_cycles[i] = other.arrival_cycles[i];
    }
}

myFIFO& myFIFO::operator=(const myFIFO& other) {
    if (this != &other) {
        champsim::modules::replacement::operator=(other);
        NUM_WAY = other.NUM_WAY;
        cycle_array_size = other.cycle_array_size;
        cycle = other.cycle;

        delete[] arrival_cycles;
        arrival_cycles = new uint64_t[cycle_array_size];
        for (size_t i = 0; i < cycle_array_size; i++) {
            arrival_cycles[i] = other.arrival_cycles[i];
        }
    }
    return *this;
}

long myFIFO::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                        champsim::address full_addr, access_type type)
{
    long set_offset = set * NUM_WAY;
    long victim_way = 0;
    uint64_t min_cycle = arrival_cycles[set_offset];

    for (long i = 1; i < NUM_WAY; i++) {
        if (arrival_cycles[set_offset + i] < min_cycle) {
            min_cycle = arrival_cycles[set_offset + i];
            victim_way = i;
        }
    }

    assert(victim_way >= 0);
    assert(victim_way < NUM_WAY);
    return victim_way;
}

void myFIFO::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                   access_type type)
{
    arrival_cycles[(size_t)(set * NUM_WAY + way)] = cycle++;
}

void myFIFO::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                     champsim::address victim_addr, access_type type, uint8_t hit)
{

}