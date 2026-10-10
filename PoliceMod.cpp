// PoliceMod v0.1 - PASSO 1: "scanner" de funcoes da policia (AML, GTA SA v2.10)
// Nao muda nada no jogo. Ao abrir o jogo, cria o arquivo:
//   Android/data/com.rockstargames.gtasa/files/PoliceMod_symbols.txt
// com os nomes das funcoes do jogo ligadas a policia/perseguicao.
// Com esse arquivo eu escrevo o mod de verdade (passo 2) sem chutar enderecos.
#include <mod/amlmod.h>
#include <mod/logger.h>
#include <link.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <thread>
#include <unistd.h>

MYMODCFG(net.user.policemod, PoliceMod, 0.1, User)

#define OUT_PATH "/storage/emulated/0/Android/data/com.rockstargames.gtasa/files/PoliceMod_symbols.txt"

static const char* FILTERS[] = {
    "Wanted", "Police", "Cop", "AutoPilot", "Autopilot", "CCarCtrl",
    "Vigilante", "Handling", "CPopulation", "CCarAI", "Pursuit", "Chase"
};

static std::string FindLibPath(const char* name)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return "";
    char line[1024];
    std::string res;
    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, name))
        {
            char* p = strchr(line, '/');
            if (p)
            {
                res = p;
                while (!res.empty() && (res.back() == '\n' || res.back() == ' ')) res.pop_back();
                break;
            }
        }
    }
    fclose(f);
    return res;
}

static bool Matches(const char* nm)
{
    for (const char* flt : FILTERS)
        if (strstr(nm, flt)) return true;
    return false;
}

static bool DumpSymbols(const std::string& path)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { logger->Error("Nao abriu %s", path.c_str()); return false; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<char> buf(sz);
    size_t rd = fread(buf.data(), 1, sz, f);
    fclose(f);
    if ((long)rd != sz) { logger->Error("Leitura incompleta"); return false; }

    ElfW(Ehdr)* eh = (ElfW(Ehdr)*)buf.data();
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) { logger->Error("Nao e ELF"); return false; }
    if (eh->e_shoff == 0 || eh->e_shoff + (size_t)eh->e_shnum * sizeof(ElfW(Shdr)) > (size_t)sz)
    { logger->Error("Sem tabela de secoes"); return false; }

    ElfW(Shdr)* sh = (ElfW(Shdr)*)(buf.data() + eh->e_shoff);
    FILE* out = fopen(OUT_PATH, "w");
    if (!out) { logger->Error("Nao criou %s", OUT_PATH); return false; }

    int total = 0, found = 0;
    for (int i = 0; i < eh->e_shnum; i++)
    {
        if (sh[i].sh_type != SHT_DYNSYM) continue;
        if (sh[i].sh_link >= eh->e_shnum) continue;
        ElfW(Sym)* syms = (ElfW(Sym)*)(buf.data() + sh[i].sh_offset);
        size_t n = sh[i].sh_size / sizeof(ElfW(Sym));
        const char* str = buf.data() + sh[sh[i].sh_link].sh_offset;
        for (size_t j = 0; j < n; j++)
        {
            total++;
            const char* nm = str + syms[j].st_name;
            if (nm[0] && Matches(nm))
            {
                fprintf(out, "%s 0x%lx\n", nm, (unsigned long)syms[j].st_value);
                found++;
            }
        }
    }
    fprintf(out, "# total=%d encontrados=%d\n", total, found);
    fclose(out);
    logger->Info("Simbolos: total=%d, policia=%d", total, found);
    return true;
}

static void ScanThread()
{
    for (int i = 0; i < 20; i++)
    {
        std::string p = FindLibPath("libGTASA.so");
        if (!p.empty()) { DumpSymbols(p); return; }
        sleep(1);
    }
    logger->Error("libGTASA.so nao achada nos maps");
}

ON_MOD_PRELOAD()
{
    logger->SetTag("PoliceMod");
    std::thread(ScanThread).detach();
}
