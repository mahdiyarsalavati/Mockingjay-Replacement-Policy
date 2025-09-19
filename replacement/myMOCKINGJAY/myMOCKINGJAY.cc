#include "myMOCKINGJAY.h"

RDP::RDP() : rdp_table(PREDICTOR_SIZE, 0) {}

int RDP::temporal_difference(int init, int sample) {
    if (sample > init) {
        int diff = (sample - init) / 16;
        return min(init + max(1, diff), INF_RD);
    }
    if (sample < init) {
        int diff = (init - sample) / 16;
        return max(init - max(1, diff), 0);
    }
    return init;
}

int RDP::predict(uint64_t pc_signature) {
    return rdp_table[pc_signature % PREDICTOR_SIZE];
}

void RDP::train(uint64_t pc_signature, int sample) {
    uint32_t index = pc_signature % PREDICTOR_SIZE;
    rdp_table[index] = temporal_difference(rdp_table[index], sample);
}


SampledCache::SampledCache(RDP& rdp_ref) : sets(NUM_SETS, vector<SampledCacheEntry>(NUM_WAYS)), rdp(rdp_ref) {}

void SampledCache::handle_access(uint64_t full_addr, uint64_t pc_signature, int set_in_llc, int current_timestamp) {
    uint32_t internal_set = set_in_llc % NUM_SETS;
    uint64_t tag = full_addr >> 12;

    int hit_way = -1;
    for (int i = 0; i < NUM_WAYS; ++i) {
        if (sets[internal_set][i].valid && sets[internal_set][i].tag == tag) {
            hit_way = i;
            break;
        }
    }

    if (hit_way != -1) {
        auto& entry = sets[internal_set][hit_way];
        int time_elapsed = (current_timestamp >= entry.timestamp) ? (current_timestamp - entry.timestamp) : (current_timestamp - entry.timestamp + 256);
        
        rdp.train(entry.pc_signature, time_elapsed);

        entry.pc_signature = pc_signature;
        entry.timestamp = current_timestamp;
    } else {
        int victim_way = -1;
        int max_age = -1;
        for (int i = 0; i < NUM_WAYS; ++i) {
            if (!sets[internal_set][i].valid) {
                victim_way = i;
                break;
            }
            int age = (current_timestamp >= sets[internal_set][i].timestamp) ? (current_timestamp - sets[internal_set][i].timestamp) : (current_timestamp - sets[internal_set][i].timestamp + 256);
            if (age > max_age) {
                max_age = age;
                victim_way = i;
            }
        }
        
        if (sets[internal_set][victim_way].valid) {
            rdp.train(sets[internal_set][victim_way].pc_signature, RDP::INF_RD);
        }

        sets[internal_set][victim_way] = {true, tag, pc_signature, current_timestamp};
    }
}


myMOCKINGJAY::myMOCKINGJAY(CACHE* cache) : 
    replacement(cache),
    NUM_SET(cache->NUM_SET),
    NUM_WAY(cache->NUM_WAY),
    etr_counters(NUM_SET, vector<int>(NUM_WAY, 0)),
    etr_clock(NUM_SET, 0),
    set_timestamps(NUM_SET, 0),
    rdp(),
    sampled_cache(rdp)
{
    for (int i = 0; i < 32; ++i) {
        sampled_set_indices.push_back(i * (NUM_SET / 32));
    }
}

myMOCKINGJAY::myMOCKINGJAY(const myMOCKINGJAY& other) :
    replacement(other),
    NUM_SET(other.NUM_SET),
    NUM_WAY(other.NUM_WAY),
    etr_counters(other.etr_counters),
    etr_clock(other.etr_clock),
    set_timestamps(other.set_timestamps),
    rdp(other.rdp),
    sampled_cache(rdp)
{}

myMOCKINGJAY& myMOCKINGJAY::operator=(const myMOCKINGJAY& other) {
    if (this != &other) {
        replacement::operator=(other);
        NUM_SET = other.NUM_SET;
        NUM_WAY = other.NUM_WAY;
        etr_counters = other.etr_counters;
        etr_clock = other.etr_clock;
        set_timestamps = other.set_timestamps;
        rdp = other.rdp;
    }
    return *this;
}


uint64_t myMOCKINGJAY::get_pc_signature(uint64_t pc, bool hit) {
    pc = (pc << 1) | (hit ? 1 : 0);
    return pc & 0x1FFF;
}

bool myMOCKINGJAY::is_sampled_set(long set) {
    return binary_search(sampled_set_indices.begin(), sampled_set_indices.end(), set);
}

long myMOCKINGJAY::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                     champsim::address full_addr, access_type type) {
    for (long i = 0; i < NUM_WAY; ++i) {
        if (!current_set[i].valid) {
            return i;
        }
    }

    uint64_t pc_signature = get_pc_signature(ip.to<uint64_t>(), false);
    int predicted_rd = rdp.predict(pc_signature);
    if (type != access_type::WRITE && (predicted_rd > MAX_RD_THRESHOLD)) {
        return NUM_WAY;
    }

    long victim_way = 0;
    int max_abs_etr = -1;
    for (long i = 0; i < NUM_WAY; ++i) {
        int current_etr = etr_counters[set][i];
        int current_abs_etr = abs(current_etr);

        if (current_abs_etr > max_abs_etr) {
            max_abs_etr = current_abs_etr;
            victim_way = i;
        } else if (current_abs_etr == max_abs_etr) {
            if (etr_counters[set][victim_way] >= 0 && current_etr < 0) {
                victim_way = i;
            }
        }
    }
    return victim_way;
}

void myMOCKINGJAY::replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                access_type type) {
    if (way >= NUM_WAY) return;
    if (type == access_type::WRITE) return;

    uint64_t pc_signature = get_pc_signature(ip.to<uint64_t>(), false);
    int predicted_rd = rdp.predict(pc_signature);

    if (predicted_rd > MAX_RD_THRESHOLD) {
        etr_counters[set][way] = INF_ETR;
    } else {
        etr_counters[set][way] = predicted_rd / GRANULARITY;
    }
}

void myMOCKINGJAY::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                  champsim::address victim_addr, access_type type, uint8_t hit) {
    if (way >= NUM_WAY) return;
    if (type == access_type::WRITE) return;

    uint64_t pc_signature = get_pc_signature(ip.to<uint64_t>(), hit);

    if (hit) {
        int predicted_rd = rdp.predict(pc_signature);
        etr_counters[set][way] = (predicted_rd > MAX_RD_THRESHOLD) ? INF_ETR : predicted_rd / GRANULARITY;
    }

    etr_clock[set]++;
    if (etr_clock[set] >= GRANULARITY) {
        etr_clock[set] = 0;
        for (int i = 0; i < NUM_WAY; ++i) {
            if (abs(etr_counters[set][i]) < INF_ETR) {
                etr_counters[set][i]--;
            }
        }
    }
    
    if (is_sampled_set(set)) {
        set_timestamps[set] = (set_timestamps[set] + 1) % 256;
        sampled_cache.handle_access(full_addr.to<uint64_t>(), pc_signature, set, set_timestamps[set]);
    }
}
