#ifndef REPLACEMENT_MYMOCKINGJAY_H
#define REPLACEMENT_MYMOCKINGJAY_H

#include "cache.h"
#include <vector>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <cassert>

using namespace std;

class RDP {
private:
    vector<int> rdp_table;
    static constexpr int PREDICTOR_SIZE = 4096;
    
    int temporal_difference(int init, int sample);

public:
    static constexpr int INF_RD = (16 * 8) - 1;

    RDP();
    int predict(uint64_t pc_signature);
    void train(uint64_t pc_signature, int sample);
};

class SampledCache {
private:
    struct SampledCacheEntry {
        bool valid = false;
        uint64_t tag = 0;
        uint64_t pc_signature = 0;
        int timestamp = 0;
    };

    vector<vector<SampledCacheEntry>> sets;
    RDP& rdp;

    static constexpr int NUM_WAYS = 5;
    static constexpr int NUM_SETS = 512;

public:
    SampledCache(RDP& rdp_ref);
    void handle_access(uint64_t full_addr, uint64_t pc_signature, int set_in_llc, int current_timestamp);
};

class myMOCKINGJAY : public champsim::modules::replacement {
private:
    long NUM_SET;
    long NUM_WAY;

    vector<vector<int>> etr_counters;
    vector<int> etr_clock;
    vector<int> set_timestamps;

    RDP rdp;
    SampledCache sampled_cache;
    vector<long> sampled_set_indices;

    static constexpr int LOG2_NUM_SET = 11;
    static constexpr int LOG2_SAMPLED_SETS = 5;

    static constexpr int GRANULARITY = 8;
    static constexpr int INF_ETR = ((16 * 8) / GRANULARITY) - 1;
    static constexpr int MAX_RD_THRESHOLD = ((16 * 8) - 1) - 22;

    uint64_t get_pc_signature(uint64_t pc, bool hit);
    bool is_sampled_set(long set);

public:
    explicit myMOCKINGJAY(CACHE* cache);
    myMOCKINGJAY(const myMOCKINGJAY& other);
    myMOCKINGJAY& operator=(const myMOCKINGJAY& other);
    ~myMOCKINGJAY() = default;

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                         champsim::address full_addr, access_type type);
    
    void replacement_cache_fill(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip, champsim::address victim_addr,
                                    access_type type);

    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                      champsim::address victim_addr, access_type type, uint8_t hit);
};

#endif