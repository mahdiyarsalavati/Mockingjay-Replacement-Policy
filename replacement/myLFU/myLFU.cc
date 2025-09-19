#include "myLFU.h"
#include <cassert>
#include <limits>

myLFU::myLFU(CACHE* cache) : myLFU(cache, cache->NUM_SET, cache->NUM_WAY) {}

myLFU::myLFU(CACHE* cache, long sets, long ways) : replacement(cache), NUM_WAY(ways) {
    block_count = (size_t)(sets * ways);
    frequency_counters = new uint64_t[block_count];
    last_used_cycles = new uint64_t[block_count];
    for (size_t i = 0; i < block_count; i++) {
        frequency_counters[i] = 0;
        last_used_cycles[i] = 0;
    }
}

myLFU::~myLFU() {
    delete[] frequency_counters;
    delete[] last_used_cycles;
}

myLFU::myLFU(const myLFU& other)
    : replacement(other), NUM_WAY(other.NUM_WAY), block_count(other.block_count), cycle(other.cycle)
{
    frequency_counters = new uint64_t[block_count];
    last_used_cycles = new uint64_t[block_count];
    for (size_t i = 0; i < block_count; i++) {
        frequency_counters[i] = other.frequency_counters[i];
        last_used_cycles[i] = other.last_used_cycles[i];
    }
}

myLFU& myLFU::operator=(const myLFU& other) {
    if (this != &other) {
        champsim::modules::replacement::operator=(other);
        NUM_WAY = other.NUM_WAY;
        block_count = other.block_count;
        cycle = other.cycle;

        delete[] frequency_counters;
        delete[] last_used_cycles;

        frequency_counters = new uint64_t[block_count];
        last_used_cycles = new uint64_t[block_count];
        for (size_t i = 0; i < block_count; i++) {
            frequency_counters[i] = other.frequency_counters[i];
            last_used_cycles[i] = other.last_used_cycles[i];
        }
    }
    return *this;
}

long myLFU::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                        champsim::address full_addr, access_type type)
{
    long set_offset = set * NUM_WAY;

    uint64_t min_freq = frequency_counters[set_offset];
    for (long i = 1; i < NUM_WAY; i++) {
        if (frequency_counters[set_offset + i] < min_freq) {
            min_freq = frequency_counters[set_offset + i];
        }
    }

    long victim_way = -1;
    uint64_t min_cycle = std::numeric_limits<uint64_t>::max();
    for (long i = 0; i < NUM_WAY; i++) {
        if (frequency_counters[set_offset + i] == min_freq) {
            if (last_used_cycles[set_offset + i] < min_cycle) {
                min_cycle = last_used_cycles[set_offset + i];
                victim_way = i;
            }
        }
    }

    assert(victim_way != -1);
    return victim_way;
}

void myLFU::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                   access_type type)
{
    size_t block_index = (size_t)(set * NUM_WAY + way);
    frequency_counters[block_index] = 1;
    last_used_cycles[block_index] = cycle++;
}

void myLFU::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                     champsim::address victim_addr, access_type type, uint8_t hit)
{
    if (hit && access_type{type} != access_type::WRITE) {
        size_t block_index = (size_t)(set * NUM_WAY + way);
        frequency_counters[block_index]++;
        last_used_cycles[block_index] = cycle++;
    }
}