#include "myLRU.h"
#include <cassert>

myLRU::myLRU(CACHE* cache) : myLRU(cache, cache->NUM_SET, cache->NUM_WAY) {}

myLRU::myLRU(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways) {
    cycle_array_size = (size_t)(sets * ways);
    last_used_cycles = new uint64_t[cycle_array_size];
    for (size_t i = 0; i < cycle_array_size; i++) {
        last_used_cycles[i] = 0;
    }
}

myLRU::~myLRU() {
    delete[] last_used_cycles;
}

myLRU::myLRU(const myLRU& other)
    : replacement(other), NUM_WAY(other.NUM_WAY), cycle_array_size(other.cycle_array_size), cycle(other.cycle)
{
    last_used_cycles = new uint64_t[cycle_array_size];
    for (size_t i = 0; i < cycle_array_size; i++) {
        last_used_cycles[i] = other.last_used_cycles[i];
    }
}

myLRU& myLRU::operator=(const myLRU& other) {
    if (this != &other) {
        champsim::modules::replacement::operator=(other);

        NUM_WAY = other.NUM_WAY;
        cycle = other.cycle;
        cycle_array_size = other.cycle_array_size;

        delete[] last_used_cycles;
        last_used_cycles = new uint64_t[cycle_array_size];
        for (size_t i = 0; i < cycle_array_size; i++) {
            last_used_cycles[i] = other.last_used_cycles[i];
        }
    }
    return *this;
}

long myLRU::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                        champsim::address full_addr, access_type type)
{
    long set_offset = set * NUM_WAY;
    long victim_way = 0;
    uint64_t min_cycle = last_used_cycles[set_offset];

    for (long i = 1; i < NUM_WAY; i++) {
        if (last_used_cycles[set_offset + i] < min_cycle) {
            min_cycle = last_used_cycles[set_offset + i];
            victim_way = i;
        }
    }

    assert(victim_way >= 0);
    assert(victim_way < NUM_WAY);
    return victim_way;
}

void myLRU::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                   access_type type)
{
    last_used_cycles[(size_t)(set * NUM_WAY + way)] = cycle++;
}

void myLRU::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                     champsim::address victim_addr, access_type type, uint8_t hit)
{
    if (hit && access_type{type} != access_type::WRITE)
        last_used_cycles[(size_t)(set * NUM_WAY + way)] = cycle++;
}