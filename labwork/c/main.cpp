/*
    This file is a proof of concept implementation (T3INF9004: Cryptanalysis und Method-Audit).
    See the python version to get a better understanding of the algorithm.

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork05
*/

#include <cstdint>
#include <cstring>
#include <iostream>
#include <chrono>

/*
    Case:
    {
      "tcid": "1150e796-be71-4d48-80ca-8aba093a410e",
      "passed_at_utc": null,
      "type": "rc4_fms",
      "assignment": {
        "captured_ivs": "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",
        "difficulty": 6,
        "key_length": 16
      },
      "expect_solution": {
        "key": "fGk/gSLJ8jmle7lljLK+VA=="
      }
    }
*/

uint8_t key[16] = {124, 105, 63, 129, 34, 201, 242, 57, 165, 123, 185, 101, 140, 178, 190, 84};

// Temp solution
// This should actually call the api. I dont feel like doing that right now. Especially without any http library's lol
bool validate(uint8_t* K) {
    return !memcmp(K, key, 16);
}

struct Block {
    uint8_t iv[3];
    uint8_t fb;
};

int32_t sizes[16];
Block* blocks[16];

struct Histogram {
    struct Entry {
        uint8_t type {};
        uint16_t count = 0;
    } entries[256];

    static void inverse(const uint8_t box[256], uint8_t buffer[256]) {
        for(int i = 0; i < 256; i++) buffer[box[i]] = i;
    }

    Histogram(uint8_t A, uint8_t K[16]) {
        for(int i = 0; i < 256; i++) (entries + i)->type = i;
        uint8_t S[256];
        uint8_t Sm1[256];
        uint8_t ksa[A+3];
        auto block = blocks[A];
        for (int32_t i = 0; i < sizes[A]; i++) {
            for(int i2 = 0; i2 < 256; i2++) S[i2] = i2;
            memcpy(ksa, block->iv, 3);
            memcpy(ksa + 3, K, A);
            uint8_t j = 0;
            for(int i2 = 0; i2 < A + 3; i2++) {
                j += S[i2] + ksa[i2];
                uint8_t t = S[i2];
                S[i2] = S[j];
                S[j] = t;
            }
            inverse(S, Sm1);
            uint8_t Z = (Sm1[block->fb] - j - S[A + 3]);
            (entries + Z)->count++;
            block++;
        }
        qsort(entries, 256, sizeof(Entry), [](const void* a, const void* b){
            return ((Entry*) b)->count - ((Entry*) a)->count;
        });
    }
};

struct Node {
    Histogram histogram;
    Node* nodes = nullptr;
    uint16_t node_count = 0;

    Node(uint8_t A, uint8_t K[16]) : histogram(A, K) {}

    // not quite as optimized as the python version, but still fast enough
    uint8_t* df_bs_search(uint8_t A, uint8_t K[16], char* F) {
        //Histogram histogram (A, K);
        if(node_count >= 256) return nullptr;
        if(A == 15) {
            K[A] = (histogram.entries + node_count)->type;
            //std::cout << F << std::endl;
            if(validate(K)) return K;
        } else {
            for(int i = 0; i < node_count; i++) {
                K[A] = (histogram.entries + i)->type;
                F[A] = (char) ('0' + i);
                auto result = nodes[i].df_bs_search(A + 1, K, F);
                if(result) return result;
            }
            K[A] = (histogram.entries + node_count)->type;
            Node node(A + 1, K);
            F[A] = (char) ('0' + node_count);

            for(int i = 0; i < node_count + 1; i++) {
                auto result = node.df_bs_search(A + 1, K, F);
                if(result) return result;
            }

            nodes = static_cast<Node*>(realloc(nodes, sizeof(Node) * (node_count + 1)));
            nodes[node_count] = node;
        }
        node_count++;
        return nullptr;
    }
};

int main() {
    FILE* file;
    // c_in.dat contains a dump of ivs
    fopen_s(&file, "../c_in.dat", "rb");
    for (int i = 0; i < 16; i++) {
        fread(sizes + i, sizeof(int32_t), 1, file);
        void* buffer = malloc(sizeof(struct Block) * sizes[i]);
        fread(buffer, sizeof(struct Block), sizes[i], file);
        blocks[i] = static_cast<Block*>(buffer);
    }
    fclose(file);

    uint8_t K[16];
    Node node(0, K);

    char F[17];
    F[16] = 0;

    // This goes f*ck*ng fast brrrr
    auto start = std::chrono::steady_clock::now();
    auto res = node.df_bs_search(0, K, F) != nullptr;
    std::cout << "Found: " << res << std::endl;
    res = node.df_bs_search(0, K, F) != nullptr;
    std::cout << "Found: " << res << std::endl;
    std::cout << "Elapsed(ms) = " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() << std::endl;
}