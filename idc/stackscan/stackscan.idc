#define UNLOADED_FILE   1
#include <idc.idc>

static CheckXrefs(curAddr) {
	auto Spd, cnt, curPtr, curSpd;
	Spd = -1;
	cnt = 0;
	curPtr = RfirstB(curAddr);
	if(curPtr == PrevNotTail(curAddr) && RnextB(curAddr, curPtr) == BADADDR) {
		return 0;
	}
	for(; curPtr != BADADDR; curPtr = RnextB(curAddr, curPtr)) {
		curSpd = -(GetSpd(NextNotTail(curPtr)));
		MakeComm(curPtr, form("spd = 0x%X", curSpd));
		if(Spd != -1 && Spd != curSpd) {
			SetColor(curPtr, 1, 0x00CC00);
			cnt = cnt + 1;
		}
		else if(Spd == -1) {
			Spd = curSpd;
		}
	}
}

static main(void) {
	auto curAddr, startAddr, endAddr, cnt, total;
	curAddr = ScreenEA();
	startAddr = GetFunctionAttr(curAddr, FUNCATTR_START);
	endAddr = GetFunctionAttr(curAddr, FUNCATTR_END);

	total = 0;

	for(curAddr = startAddr; curAddr != endAddr; curAddr = NextNotTail(curAddr)) {
		cnt = CheckXrefs(curAddr);
		if(cnt) {
			MakeComm(curAddr, form("errors: %d\n", cnt));
			SetColor(curAddr, 1, 0xCC0000);
			total = total + cnt;
		}
	}
	if(total) {
		Message("Total errors: %d\n", total);
	}
}