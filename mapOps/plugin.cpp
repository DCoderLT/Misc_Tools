/*
 * this plugin scans the currently selected area for data flow (reads/writes)
 * currently it only supports r/w to general registers
 */

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <struct.hpp>
#include <typeinf.hpp>

#include <intel.hpp>
#include <vector>
#include <unordered_map>
#include <algorithm>

//--------------------------------------------------------------------------
int idaapi init(void)
{
	return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
}

class op_acc_type {
public:
	enum {
		T_NONE = 0,
		T_READ = 1,
		T_WRITE = 2
	};
	typedef unsigned int Value;
};

struct op_acc {
	ea_t firstRead;
	ea_t lastWrite;
};

struct op_ident {
	int regIdx;
	int stkOffs;
	op_ident(int _reg = 0, int _stk = 0) : regIdx(_reg), stkOffs(_stk) {};

	void normalizeReg() {
		if(regIdx >= R_al && regIdx <= R_bh) {
			regIdx -= R_al;
			regIdx &= 3;
		}
	}

	struct hasher {
		bool operator()(const op_ident &op) const {
			return op.regIdx << 16 | op.stkOffs;
		}
	};

	struct eq {
		bool operator()(const op_ident &lhs, const op_ident &rhs) const {
			return lhs.regIdx == rhs.regIdx && lhs.stkOffs == rhs.stkOffs;
		}
	};
};

std::unordered_map<op_ident, op_acc, op_ident::hasher, op_ident::eq> op_usage;

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
	ea_t eaStart, eaEnd;
	if(!read_selection(&eaStart, &eaEnd)) {
		eaStart = get_screen_ea();
		eaEnd = next_head(eaStart, eaStart + 0x100);
	}
	area_t sel(eaStart, eaEnd);

	reginfovec_t readRegs, writeRegs;

	uint32 getterFlags[UA_MAXOP] = { CF_USE1, CF_USE2, CF_USE3, CF_USE4, CF_USE5, CF_USE6 };
	uint32 setterFlags[UA_MAXOP] = { CF_CHG1, CF_CHG2, CF_CHG3, CF_CHG4, CF_CHG5, CF_CHG6 };

	op_usage.clear();

	for(auto tmpEa = sel.startEA; tmpEa < sel.endEA; tmpEa = next_head(tmpEa, sel.endEA + 1)) {
		auto eaFlags = getFlags(tmpEa);
		if(isCode(eaFlags)) {
			decode_insn(tmpEa);
			if(cmd.is_canon_insn()) {
				for(auto i = 0; i < UA_MAXOP; ++i) {
					const auto &op = cmd.Operands[i];
					op_acc_type::Value usage(op_acc_type::T_NONE);
					if(InstrIsSet(cmd.itype, getterFlags[i])) {
						usage |= op_acc_type::T_READ;
					}

					if(InstrIsSet(cmd.itype, setterFlags[i])) {
						usage |= op_acc_type::T_WRITE;
					}

					if(usage != op_acc_type::T_NONE) {
						std::vector<op_ident> affectedRegs;
						switch(op.type) {
						case o_reg:
							{
								op_ident r(op.reg);
								r.normalizeReg();
								affectedRegs.push_back(r);
							}
							break;

						case o_phrase:
							{
								auto r_base = x86_base(op);
								op_ident id_base(r_base);
								id_base.normalizeReg();

								affectedRegs.push_back(id_base);
								if(op.specflag1) {
									auto r_index = x86_index(op);
									op_ident id_index(r_index);
									id_index.normalizeReg();
									affectedRegs.push_back(id_index);
								}
							}
							break;

						case o_displ:
							{
								auto r_base = x86_base(op);
								op_ident id_base(r_base);
								id_base.normalizeReg();

								affectedRegs.push_back(id_base);
								if(op.specflag1) {
									auto r_index = x86_index(op);
									op_ident id_index(r_index, op.addr);
									id_index.normalizeReg();
									affectedRegs.push_back(id_index);
								}
							}
							break;
						}

						std::for_each(affectedRegs.begin(), affectedRegs.end(), [tmpEa, usage](const op_ident &ident) -> void {
							auto exist = op_usage.find(ident);
							bool isRead = !!(usage & op_acc_type::T_READ);
							bool isWrite = !!(usage & op_acc_type::T_WRITE);
							if(exist == op_usage.end()) {
								op_acc newUsage = { BADADDR, BADADDR };
								if(isRead) {
									newUsage.firstRead = tmpEa;
								}
								if(isWrite) {
									newUsage.lastWrite = tmpEa;
								}
								op_usage[ident] = newUsage;
							} else {
								auto &oldUsage = (*exist).second;
								if(isRead) {
									if(oldUsage.firstRead == BADADDR || oldUsage.firstRead > tmpEa) {
										oldUsage.firstRead = tmpEa;
									}
								}
								if(isWrite) {
									if(oldUsage.lastWrite == BADADDR || oldUsage.lastWrite < tmpEa) {
										oldUsage.lastWrite = tmpEa;
									}
								}
							}
						});
					}


				}
			}
		}
	}

	auto F = get_func(sel.startEA);

	char funcName[MAXNAMELEN];
	if(!get_func_name(F->startEA, funcName, sizeof(funcName))) {
		_snprintf(funcName, sizeof(funcName), "UNKNOWN_%X", F->startEA);
	}

	qstring output;
	output.sprnt("DEFINE_HOOK(%X, %s, %X) {\n", sel.startEA, funcName, std::min(5U, sel.endEA - sel.startEA));

	auto startESP = -get_spd(F, sel.startEA);
	auto endESP = -get_spd(F, prev_head(sel.endEA, sel.startEA));
	if(startESP != endESP) {
		output.cat_sprnt("\t// stack modification detected (0x%X -> 0x%X)!\n", startESP, endESP);
	}

	qstring reads;
	qstring writes;

	std::for_each(op_usage.begin(), op_usage.end(), [&reads, &writes](const std::pair<const op_ident, op_acc>& p) -> void {
		bool isRead = (p.second.firstRead != BADADDR);
		bool isWrite = (p.second.lastWrite != BADADDR);
		auto readStatus = isRead ? 'R' : ' ';
		auto writeStatus = isWrite ? 'W' : ' ';

		if(p.first.regIdx == R_sp) {
			auto offs = p.first.stkOffs;
			//stkvar

			if(isRead) {
				reads.cat_sprnt("\tGET_STACK(DWORD, rs_%x, 0x%x);\n", offs, offs);
			}
			if(isWrite) {
				writes.cat_sprnt("\tR->Stack<DWORD>(0x%x, w_%x);\n", offs, offs);
			}

		} else {
			// general reg
			char regName[0x80];
			if(get_reg_name(p.first.regIdx, 4, regName, sizeof(regName)) == -1) {
				strncpy(regName, "Unknown", 8);
			}
			strupr(regName);
			msg("Register %s (%d): %c%c\n", regName, p.first.regIdx, readStatus, writeStatus);
			if(isRead) {
				reads.cat_sprnt("\tGET(DWORD, r_%s, %s);\n", regName, regName);
			}
			if(isWrite) {
				writes.cat_sprnt("\tR->%s<DWORD>(w_%s);\n", regName, regName);
			}
		}
	});

	output.cat_sprnt("%s\n\t/// Code goes here\n%s\n\treturn 0x%X;\n}", reads.c_str(), writes.c_str(), sel.endEA);

	if(auto freethiscrap = asktext(0, NULL, output.c_str(), "Copy/paste this into your IDE!")) {
		delete [] freethiscrap;
	}
}

//--------------------------------------------------------------------------
char comment[] = "Get data flow";

char help[] = "Determine data flow within selection\n";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Get Data Flow";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,                    // plugin flags
	init,                 // initialize

	term,                 // terminate. this pointer may be NULL.

	run,                  // invoke plugin

	comment,              // long comment about the plugin
	// it could appear in the status line
	// or as a hint

	help,                 // multiline help about the plugin

	wanted_name,          // the preferred short name of the plugin
	wanted_hotkey         // the preferred hotkey to run the plugin
};
