from elftools.elf.elffile import ELFFile
from capstone import *
import networkx as nx
from collections import Counter
import sys

# ------------------------------------------------------------
# ELF PARSER
# ------------------------------------------------------------

def parse_elf(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)

        entry = elf.header["e_entry"]
        arch = elf.header["e_machine"]

        sections = []
        for sec in elf.iter_sections():
            sections.append({
                "name": sec.name,
                "addr": sec["sh_addr"],
                "size": sec["sh_size"]
            })

        return {
            "entry": entry,
            "arch": arch,
            "sections": sections,
            "elf": elf
        }

# ------------------------------------------------------------
# DISASSEMBLY
# ------------------------------------------------------------

def get_disassembler():
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    return cs


def disassemble_code(code, base_addr, cs):
    instructions = []
    for insn in cs.disasm(code, base_addr):
        instructions.append(insn)
    return instructions

# ------------------------------------------------------------
# BASIC BLOCK
# ------------------------------------------------------------

class BasicBlock:
    def __init__(self, start_addr):
        self.start_addr = start_addr
        self.instructions = []
        self.successors = set()

# ------------------------------------------------------------
# CFG BUILDER
# ------------------------------------------------------------

def build_cfg(instructions):
    cfg = nx.DiGraph()
    current_block = None

    for insn in instructions:
        if current_block is None:
            current_block = BasicBlock(insn.address)

        current_block.instructions.append(insn)

        # Control-flow instruction
        if insn.mnemonic.startswith(("j", "ret", "call")):
            cfg.add_node(current_block.start_addr, block=current_block)

            # Try to extract jump target
            if insn.operands:
                for op in insn.operands:
                    if op.type == CS_OP_IMM:
                        target = op.imm
                        cfg.add_edge(current_block.start_addr, target)
                        current_block.successors.add(target)

            current_block = None

    # Add last block if it exists
    if current_block:
        cfg.add_node(current_block.start_addr, block=current_block)

    return cfg

# ------------------------------------------------------------
# OPCODE FREQUENCY
# ------------------------------------------------------------

def opcode_frequency(instructions):
    freq = Counter()
    for insn in instructions:
        freq[insn.mnemonic] += 1
    return freq

# ------------------------------------------------------------
# MAIN ANALYSIS PIPELINE
# ------------------------------------------------------------

def analyze_binary(path):
    info = parse_elf(path)
    elf = info["elf"]

    text = elf.get_section_by_name(".text")
    if not text:
        raise RuntimeError("No .text section found")

    code = text.data()
    base_addr = text["sh_addr"]

    cs = get_disassembler()
    instructions = disassemble_code(code, base_addr, cs)

    cfg = build_cfg(instructions)
    freq = opcode_frequency(instructions)

    return {
        "entry_point": info["entry"],
        "instruction_count": len(instructions),
        "basic_blocks": cfg.number_of_nodes(),
        "edges": cfg.number_of_edges(),
        "opcode_frequency": freq,
        "cfg": cfg
    }

# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <elf_binary>")
        sys.exit(1)

    result = analyze_binary(sys.argv[1])

    print("\n=== Analysis Results ===")
    print(f"Entry point: 0x{result['entry_point']:x}")
    print(f"Instructions: {result['instruction_count']}")
    print(f"Basic blocks: {result['basic_blocks']}")
    print(f"CFG edges: {result['edges']}")

    print("\nTop 10 opcodes:")
    for op, count in result["opcode_frequency"].most_common(10):
        print(f"{op:8} {count}")
