#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#pragma pack(1)

FARPROC p[814] = {0};

extern "C" BOOL WINAPI DllMain(HINSTANCE hInst,DWORD reason,LPVOID)
{
	static HINSTANCE hL;
	if (reason == DLL_PROCESS_ATTACH)
	{
		hL = LoadLibrary(_T(".\\Storm_org.dll"));
		if (!hL) return false;
		p[0] = GetProcAddress(hL,(const char *)448);
		p[1] = GetProcAddress(hL,(const char *)753);
		p[2] = GetProcAddress(hL,(const char *)752);
		p[3] = GetProcAddress(hL,(const char *)751);
		p[4] = GetProcAddress(hL,(const char *)750);
		p[5] = GetProcAddress(hL,(const char *)749);
		p[6] = GetProcAddress(hL,(const char *)748);
		p[7] = GetProcAddress(hL,(const char *)747);
		p[8] = GetProcAddress(hL,(const char *)746);
		p[9] = GetProcAddress(hL,(const char *)745);
		p[10] = GetProcAddress(hL,(const char *)744);
		p[11] = GetProcAddress(hL,(const char *)743);
		p[12] = GetProcAddress(hL,(const char *)742);
		p[13] = GetProcAddress(hL,(const char *)741);
		p[14] = GetProcAddress(hL,(const char *)740);
		p[15] = GetProcAddress(hL,(const char *)739);
		p[16] = GetProcAddress(hL,(const char *)738);
		p[17] = GetProcAddress(hL,(const char *)737);
		p[18] = GetProcAddress(hL,(const char *)736);
		p[19] = GetProcAddress(hL,(const char *)735);
		p[20] = GetProcAddress(hL,(const char *)734);
		p[21] = GetProcAddress(hL,(const char *)733);
		p[22] = GetProcAddress(hL,(const char *)732);
		p[23] = GetProcAddress(hL,(const char *)731);
		p[24] = GetProcAddress(hL,(const char *)730);
		p[25] = GetProcAddress(hL,(const char *)729);
		p[26] = GetProcAddress(hL,(const char *)728);
		p[27] = GetProcAddress(hL,(const char *)727);
		p[28] = GetProcAddress(hL,(const char *)726);
		p[29] = GetProcAddress(hL,(const char *)725);
		p[30] = GetProcAddress(hL,(const char *)724);
		p[31] = GetProcAddress(hL,(const char *)723);
		p[32] = GetProcAddress(hL,(const char *)722);
		p[33] = GetProcAddress(hL,(const char *)721);
		p[34] = GetProcAddress(hL,(const char *)720);
		p[35] = GetProcAddress(hL,(const char *)719);
		p[36] = GetProcAddress(hL,(const char *)718);
		p[37] = GetProcAddress(hL,(const char *)717);
		p[38] = GetProcAddress(hL,(const char *)716);
		p[39] = GetProcAddress(hL,(const char *)715);
		p[40] = GetProcAddress(hL,(const char *)714);
		p[41] = GetProcAddress(hL,(const char *)713);
		p[42] = GetProcAddress(hL,(const char *)900);
		p[43] = GetProcAddress(hL,(const char *)899);
		p[44] = GetProcAddress(hL,(const char *)898);
		p[45] = GetProcAddress(hL,(const char *)897);
		p[46] = GetProcAddress(hL,(const char *)896);
		p[47] = GetProcAddress(hL,(const char *)895);
		p[48] = GetProcAddress(hL,(const char *)894);
		p[49] = GetProcAddress(hL,(const char *)893);
		p[50] = GetProcAddress(hL,(const char *)892);
		p[51] = GetProcAddress(hL,(const char *)712);
		p[52] = GetProcAddress(hL,(const char *)711);
		p[53] = GetProcAddress(hL,(const char *)195);
		p[54] = GetProcAddress(hL,(const char *)196);
		p[55] = GetProcAddress(hL,(const char *)197);
		p[56] = GetProcAddress(hL,(const char *)198);
		p[57] = GetProcAddress(hL,(const char *)199);
		p[58] = GetProcAddress(hL,(const char *)200);
		p[59] = GetProcAddress(hL,(const char *)710);
		p[60] = GetProcAddress(hL,(const char *)709);
		p[61] = GetProcAddress(hL,(const char *)708);
		p[62] = GetProcAddress(hL,(const char *)707);
		p[63] = GetProcAddress(hL,(const char *)706);
		p[64] = GetProcAddress(hL,(const char *)705);
		p[65] = GetProcAddress(hL,(const char *)207);
		p[66] = GetProcAddress(hL,(const char *)704);
		p[67] = GetProcAddress(hL,(const char *)703);
		p[68] = GetProcAddress(hL,(const char *)702);
		p[69] = GetProcAddress(hL,(const char *)701);
		p[70] = GetProcAddress(hL,(const char *)700);
		p[71] = GetProcAddress(hL,(const char *)699);
		p[72] = GetProcAddress(hL,(const char *)698);
		p[73] = GetProcAddress(hL,(const char *)697);
		p[74] = GetProcAddress(hL,(const char *)696);
		p[75] = GetProcAddress(hL,(const char *)695);
		p[76] = GetProcAddress(hL,(const char *)694);
		p[77] = GetProcAddress(hL,(const char *)693);
		p[78] = GetProcAddress(hL,(const char *)692);
		p[79] = GetProcAddress(hL,(const char *)691);
		p[80] = GetProcAddress(hL,(const char *)690);
		p[81] = GetProcAddress(hL,(const char *)689);
		p[82] = GetProcAddress(hL,(const char *)224);
		p[83] = GetProcAddress(hL,(const char *)225);
		p[84] = GetProcAddress(hL,(const char *)226);
		p[85] = GetProcAddress(hL,(const char *)227);
		p[86] = GetProcAddress(hL,(const char *)228);
		p[87] = GetProcAddress(hL,(const char *)229);
		p[88] = GetProcAddress(hL,(const char *)230);
		p[89] = GetProcAddress(hL,(const char *)231);
		p[90] = GetProcAddress(hL,(const char *)232);
		p[91] = GetProcAddress(hL,(const char *)233);
		p[92] = GetProcAddress(hL,(const char *)234);
		p[93] = GetProcAddress(hL,(const char *)235);
		p[94] = GetProcAddress(hL,(const char *)236);
		p[95] = GetProcAddress(hL,(const char *)237);
		p[96] = GetProcAddress(hL,(const char *)238);
		p[97] = GetProcAddress(hL,(const char *)239);
		p[98] = GetProcAddress(hL,(const char *)240);
		p[99] = GetProcAddress(hL,(const char *)241);
		p[100] = GetProcAddress(hL,(const char *)242);
		p[101] = GetProcAddress(hL,(const char *)243);
		p[102] = GetProcAddress(hL,(const char *)244);
		p[103] = GetProcAddress(hL,(const char *)245);
		p[104] = GetProcAddress(hL,(const char *)246);
		p[105] = GetProcAddress(hL,(const char *)247);
		p[106] = GetProcAddress(hL,(const char *)248);
		p[107] = GetProcAddress(hL,(const char *)249);
		p[108] = GetProcAddress(hL,(const char *)250);
		p[109] = GetProcAddress(hL,(const char *)688);
		p[110] = GetProcAddress(hL,(const char *)687);
		p[111] = GetProcAddress(hL,(const char *)686);
		p[112] = GetProcAddress(hL,(const char *)685);
		p[113] = GetProcAddress(hL,(const char *)684);
		p[114] = GetProcAddress(hL,(const char *)683);
		p[115] = GetProcAddress(hL,(const char *)682);
		p[116] = GetProcAddress(hL,(const char *)681);
		p[117] = GetProcAddress(hL,(const char *)680);
		p[118] = GetProcAddress(hL,(const char *)679);
		p[119] = GetProcAddress(hL,(const char *)678);
		p[120] = GetProcAddress(hL,(const char *)677);
		p[121] = GetProcAddress(hL,(const char *)676);
		p[122] = GetProcAddress(hL,(const char *)675);
		p[123] = GetProcAddress(hL,(const char *)674);
		p[124] = GetProcAddress(hL,(const char *)673);
		p[125] = GetProcAddress(hL,(const char *)672);
		p[126] = GetProcAddress(hL,(const char *)671);
		p[127] = GetProcAddress(hL,(const char *)670);
		p[128] = GetProcAddress(hL,(const char *)669);
		p[129] = GetProcAddress(hL,(const char *)668);
		p[130] = GetProcAddress(hL,(const char *)667);
		p[131] = GetProcAddress(hL,(const char *)666);
		p[132] = GetProcAddress(hL,(const char *)665);
		p[133] = GetProcAddress(hL,(const char *)664);
		p[134] = GetProcAddress(hL,(const char *)663);
		p[135] = GetProcAddress(hL,(const char *)662);
		p[136] = GetProcAddress(hL,(const char *)661);
		p[137] = GetProcAddress(hL,(const char *)660);
		p[138] = GetProcAddress(hL,(const char *)659);
		p[139] = GetProcAddress(hL,(const char *)658);
		p[140] = GetProcAddress(hL,(const char *)657);
		p[141] = GetProcAddress(hL,(const char *)656);
		p[142] = GetProcAddress(hL,(const char *)655);
		p[143] = GetProcAddress(hL,(const char *)755);
		p[144] = GetProcAddress(hL,(const char *)756);
		p[145] = GetProcAddress(hL,(const char *)757);
		p[146] = GetProcAddress(hL,(const char *)758);
		p[147] = GetProcAddress(hL,(const char *)759);
		p[148] = GetProcAddress(hL,(const char *)760);
		p[149] = GetProcAddress(hL,(const char *)600);
		p[150] = GetProcAddress(hL,(const char *)599);
		p[151] = GetProcAddress(hL,(const char *)761);
		p[152] = GetProcAddress(hL,(const char *)762);
		p[153] = GetProcAddress(hL,(const char *)763);
		p[154] = GetProcAddress(hL,(const char *)764);
		p[155] = GetProcAddress(hL,(const char *)765);
		p[156] = GetProcAddress(hL,(const char *)766);
		p[157] = GetProcAddress(hL,(const char *)767);
		p[158] = GetProcAddress(hL,(const char *)768);
		p[159] = GetProcAddress(hL,(const char *)891);
		p[160] = GetProcAddress(hL,(const char *)890);
		p[161] = GetProcAddress(hL,(const char *)889);
		p[162] = GetProcAddress(hL,(const char *)888);
		p[163] = GetProcAddress(hL,(const char *)305);
		p[164] = GetProcAddress(hL,(const char *)306);
		p[165] = GetProcAddress(hL,(const char *)307);
		p[166] = GetProcAddress(hL,(const char *)308);
		p[167] = GetProcAddress(hL,(const char *)309);
		p[168] = GetProcAddress(hL,(const char *)310);
		p[169] = GetProcAddress(hL,(const char *)311);
		p[170] = GetProcAddress(hL,(const char *)769);
		p[171] = GetProcAddress(hL,(const char *)770);
		p[172] = GetProcAddress(hL,(const char *)771);
		p[173] = GetProcAddress(hL,(const char *)772);
		p[174] = GetProcAddress(hL,(const char *)316);
		p[175] = GetProcAddress(hL,(const char *)317);
		p[176] = GetProcAddress(hL,(const char *)318);
		p[177] = GetProcAddress(hL,(const char *)319);
		p[178] = GetProcAddress(hL,(const char *)320);
		p[179] = GetProcAddress(hL,(const char *)773);
		p[180] = GetProcAddress(hL,(const char *)322);
		p[181] = GetProcAddress(hL,(const char *)774);
		p[182] = GetProcAddress(hL,(const char *)775);
		p[183] = GetProcAddress(hL,(const char *)776);
		p[184] = GetProcAddress(hL,(const char *)777);
		p[185] = GetProcAddress(hL,(const char *)327);
		p[186] = GetProcAddress(hL,(const char *)328);
		p[187] = GetProcAddress(hL,(const char *)329);
		p[188] = GetProcAddress(hL,(const char *)330);
		p[189] = GetProcAddress(hL,(const char *)778);
		p[190] = GetProcAddress(hL,(const char *)779);
		p[191] = GetProcAddress(hL,(const char *)333);
		p[192] = GetProcAddress(hL,(const char *)780);
		p[193] = GetProcAddress(hL,(const char *)781);
		p[194] = GetProcAddress(hL,(const char *)336);
		p[195] = GetProcAddress(hL,(const char *)337);
		p[196] = GetProcAddress(hL,(const char *)338);
		p[197] = GetProcAddress(hL,(const char *)339);
		p[198] = GetProcAddress(hL,(const char *)340);
		p[199] = GetProcAddress(hL,(const char *)782);
		p[200] = GetProcAddress(hL,(const char *)783);
		p[201] = GetProcAddress(hL,(const char *)784);
		p[202] = GetProcAddress(hL,(const char *)785);
		p[203] = GetProcAddress(hL,(const char *)786);
		p[204] = GetProcAddress(hL,(const char *)787);
		p[205] = GetProcAddress(hL,(const char *)788);
		p[206] = GetProcAddress(hL,(const char *)789);
		p[207] = GetProcAddress(hL,(const char *)790);
		p[208] = GetProcAddress(hL,(const char *)791);
		p[209] = GetProcAddress(hL,(const char *)792);
		p[210] = GetProcAddress(hL,(const char *)793);
		p[211] = GetProcAddress(hL,(const char *)794);
		p[212] = GetProcAddress(hL,(const char *)795);
		p[213] = GetProcAddress(hL,(const char *)796);
		p[214] = GetProcAddress(hL,(const char *)797);
		p[215] = GetProcAddress(hL,(const char *)798);
		p[216] = GetProcAddress(hL,(const char *)799);
		p[217] = GetProcAddress(hL,(const char *)800);
		p[218] = GetProcAddress(hL,(const char *)360);
		p[219] = GetProcAddress(hL,(const char *)361);
		p[220] = GetProcAddress(hL,(const char *)362);
		p[221] = GetProcAddress(hL,(const char *)363);
		p[222] = GetProcAddress(hL,(const char *)364);
		p[223] = GetProcAddress(hL,(const char *)365);
		p[224] = GetProcAddress(hL,(const char *)366);
		p[225] = GetProcAddress(hL,(const char *)367);
		p[226] = GetProcAddress(hL,(const char *)368);
		p[227] = GetProcAddress(hL,(const char *)369);
		p[228] = GetProcAddress(hL,(const char *)370);
		p[229] = GetProcAddress(hL,(const char *)371);
		p[230] = GetProcAddress(hL,(const char *)801);
		p[231] = GetProcAddress(hL,(const char *)802);
		p[232] = GetProcAddress(hL,(const char *)803);
		p[233] = GetProcAddress(hL,(const char *)804);
		p[234] = GetProcAddress(hL,(const char *)805);
		p[235] = GetProcAddress(hL,(const char *)806);
		p[236] = GetProcAddress(hL,(const char *)807);
		p[237] = GetProcAddress(hL,(const char *)379);
		p[238] = GetProcAddress(hL,(const char *)380);
		p[239] = GetProcAddress(hL,(const char *)808);
		p[240] = GetProcAddress(hL,(const char *)809);
		p[241] = GetProcAddress(hL,(const char *)810);
		p[242] = GetProcAddress(hL,(const char *)384);
		p[243] = GetProcAddress(hL,(const char *)811);
		p[244] = GetProcAddress(hL,(const char *)526);
		p[245] = GetProcAddress(hL,(const char *)812);
		p[246] = GetProcAddress(hL,(const char *)813);
		p[247] = GetProcAddress(hL,(const char *)814);
		p[248] = GetProcAddress(hL,(const char *)522);
		p[249] = GetProcAddress(hL,(const char *)815);
		p[250] = GetProcAddress(hL,(const char *)520);
		p[251] = GetProcAddress(hL,(const char *)816);
		p[252] = GetProcAddress(hL,(const char *)394);
		p[253] = GetProcAddress(hL,(const char *)395);
		p[254] = GetProcAddress(hL,(const char *)396);
		p[255] = GetProcAddress(hL,(const char *)397);
		p[256] = GetProcAddress(hL,(const char *)398);
		p[257] = GetProcAddress(hL,(const char *)887);
		p[258] = GetProcAddress(hL,(const char *)400);
		p[259] = GetProcAddress(hL,(const char *)886);
		p[260] = GetProcAddress(hL,(const char *)402);
		p[261] = GetProcAddress(hL,(const char *)885);
		p[262] = GetProcAddress(hL,(const char *)884);
		p[263] = GetProcAddress(hL,(const char *)883);
		p[264] = GetProcAddress(hL,(const char *)882);
		p[265] = GetProcAddress(hL,(const char *)407);
		p[266] = GetProcAddress(hL,(const char *)408);
		p[267] = GetProcAddress(hL,(const char *)409);
		p[268] = GetProcAddress(hL,(const char *)410);
		p[269] = GetProcAddress(hL,(const char *)411);
		p[270] = GetProcAddress(hL,(const char *)881);
		p[271] = GetProcAddress(hL,(const char *)880);
		p[272] = GetProcAddress(hL,(const char *)879);
		p[273] = GetProcAddress(hL,(const char *)878);
		p[274] = GetProcAddress(hL,(const char *)877);
		p[275] = GetProcAddress(hL,(const char *)876);
		p[276] = GetProcAddress(hL,(const char *)875);
		p[277] = GetProcAddress(hL,(const char *)874);
		p[278] = GetProcAddress(hL,(const char *)873);
		p[279] = GetProcAddress(hL,(const char *)872);
		p[280] = GetProcAddress(hL,(const char *)871);
		p[281] = GetProcAddress(hL,(const char *)870);
		p[282] = GetProcAddress(hL,(const char *)869);
		p[283] = GetProcAddress(hL,(const char *)868);
		p[284] = GetProcAddress(hL,(const char *)867);
		p[285] = GetProcAddress(hL,(const char *)866);
		p[286] = GetProcAddress(hL,(const char *)865);
		p[287] = GetProcAddress(hL,(const char *)864);
		p[288] = GetProcAddress(hL,(const char *)863);
		p[289] = GetProcAddress(hL,(const char *)862);
		p[290] = GetProcAddress(hL,(const char *)861);
		p[291] = GetProcAddress(hL,(const char *)860);
		p[292] = GetProcAddress(hL,(const char *)859);
		p[293] = GetProcAddress(hL,(const char *)435);
		p[294] = GetProcAddress(hL,(const char *)858);
		p[295] = GetProcAddress(hL,(const char *)857);
		p[296] = GetProcAddress(hL,(const char *)856);
		p[297] = GetProcAddress(hL,(const char *)855);
		p[298] = GetProcAddress(hL,(const char *)854);
		p[299] = GetProcAddress(hL,(const char *)853);
		p[300] = GetProcAddress(hL,(const char *)852);
		p[301] = GetProcAddress(hL,(const char *)851);
		p[302] = GetProcAddress(hL,(const char *)850);
		p[303] = GetProcAddress(hL,(const char *)849);
		p[304] = GetProcAddress(hL,(const char *)848);
		p[305] = GetProcAddress(hL,(const char *)847);
		p[306] = GetProcAddress(hL,(const char *)754);
		p[307] = GetProcAddress(hL,(const char *)449);
		p[308] = GetProcAddress(hL,(const char *)450);
		p[309] = GetProcAddress(hL,(const char *)451);
		p[310] = GetProcAddress(hL,(const char *)452);
		p[311] = GetProcAddress(hL,(const char *)453);
		p[312] = GetProcAddress(hL,(const char *)454);
		p[313] = GetProcAddress(hL,(const char *)455);
		p[314] = GetProcAddress(hL,(const char *)456);
		p[315] = GetProcAddress(hL,(const char *)457);
		p[316] = GetProcAddress(hL,(const char *)458);
		p[317] = GetProcAddress(hL,(const char *)459);
		p[318] = GetProcAddress(hL,(const char *)817);
		p[319] = GetProcAddress(hL,(const char *)818);
		p[320] = GetProcAddress(hL,(const char *)819);
		p[321] = GetProcAddress(hL,(const char *)820);
		p[322] = GetProcAddress(hL,(const char *)821);
		p[323] = GetProcAddress(hL,(const char *)822);
		p[324] = GetProcAddress(hL,(const char *)823);
		p[325] = GetProcAddress(hL,(const char *)824);
		p[326] = GetProcAddress(hL,(const char *)825);
		p[327] = GetProcAddress(hL,(const char *)826);
		p[328] = GetProcAddress(hL,(const char *)827);
		p[329] = GetProcAddress(hL,(const char *)828);
		p[330] = GetProcAddress(hL,(const char *)829);
		p[331] = GetProcAddress(hL,(const char *)505);
		p[332] = GetProcAddress(hL,(const char *)830);
		p[333] = GetProcAddress(hL,(const char *)831);
		p[334] = GetProcAddress(hL,(const char *)832);
		p[335] = GetProcAddress(hL,(const char *)833);
		p[336] = GetProcAddress(hL,(const char *)500);
		p[337] = GetProcAddress(hL,(const char *)499);
		p[338] = GetProcAddress(hL,(const char *)834);
		p[339] = GetProcAddress(hL,(const char *)846);
		p[340] = GetProcAddress(hL,(const char *)845);
		p[341] = GetProcAddress(hL,(const char *)844);
		p[342] = GetProcAddress(hL,(const char *)843);
		p[343] = GetProcAddress(hL,(const char *)842);
		p[344] = GetProcAddress(hL,(const char *)841);
		p[345] = GetProcAddress(hL,(const char *)840);
		p[346] = GetProcAddress(hL,(const char *)839);
		p[347] = GetProcAddress(hL,(const char *)838);
		p[348] = GetProcAddress(hL,(const char *)837);
		p[349] = GetProcAddress(hL,(const char *)836);
		p[350] = GetProcAddress(hL,(const char *)492);
		p[351] = GetProcAddress(hL,(const char *)493);
		p[352] = GetProcAddress(hL,(const char *)494);
		p[353] = GetProcAddress(hL,(const char *)495);
		p[354] = GetProcAddress(hL,(const char *)835);
		p[355] = GetProcAddress(hL,(const char *)595);
		p[356] = GetProcAddress(hL,(const char *)593);
		p[357] = GetProcAddress(hL,(const char *)594);
		p[358] = GetProcAddress(hL,(const char *)603);
		p[359] = GetProcAddress(hL,(const char *)616);
		p[360] = GetProcAddress(hL,(const char *)646);
		p[361] = GetProcAddress(hL,(const char *)601);
		p[362] = GetProcAddress(hL,(const char *)602);
		p[363] = GetProcAddress(hL,(const char *)654);
		p[364] = GetProcAddress(hL,(const char *)605);
		p[365] = GetProcAddress(hL,(const char *)609);
		p[366] = GetProcAddress(hL,(const char *)610);
		p[367] = GetProcAddress(hL,(const char *)611);
		p[368] = GetProcAddress(hL,(const char *)612);
		p[369] = GetProcAddress(hL,(const char *)614);
		p[370] = GetProcAddress(hL,(const char *)617);
		p[371] = GetProcAddress(hL,(const char *)618);
		p[372] = GetProcAddress(hL,(const char *)620);
		p[373] = GetProcAddress(hL,(const char *)625);
		p[374] = GetProcAddress(hL,(const char *)626);
		p[375] = GetProcAddress(hL,(const char *)630);
		p[376] = GetProcAddress(hL,(const char *)631);
		p[377] = GetProcAddress(hL,(const char *)632);
		p[378] = GetProcAddress(hL,(const char *)633);
		p[379] = GetProcAddress(hL,(const char *)634);
		p[380] = GetProcAddress(hL,(const char *)636);
		p[381] = GetProcAddress(hL,(const char *)647);
		p[382] = GetProcAddress(hL,(const char *)604);
		p[383] = GetProcAddress(hL,(const char *)607);
		p[384] = GetProcAddress(hL,(const char *)613);
		p[385] = GetProcAddress(hL,(const char *)621);
		p[386] = GetProcAddress(hL,(const char *)624);
		p[387] = GetProcAddress(hL,(const char *)637);
		p[388] = GetProcAddress(hL,(const char *)638);
		p[389] = GetProcAddress(hL,(const char *)639);
		p[390] = GetProcAddress(hL,(const char *)640);
		p[391] = GetProcAddress(hL,(const char *)641);
		p[392] = GetProcAddress(hL,(const char *)642);
		p[393] = GetProcAddress(hL,(const char *)643);
		p[394] = GetProcAddress(hL,(const char *)644);
		p[395] = GetProcAddress(hL,(const char *)645);
		p[396] = GetProcAddress(hL,(const char *)606);
		p[397] = GetProcAddress(hL,(const char *)622);
		p[398] = GetProcAddress(hL,(const char *)623);
		p[399] = GetProcAddress(hL,(const char *)627);
		p[400] = GetProcAddress(hL,(const char *)629);
		p[401] = GetProcAddress(hL,(const char *)635);
		p[402] = GetProcAddress(hL,(const char *)615);
		p[403] = GetProcAddress(hL,(const char *)628);
		p[404] = GetProcAddress(hL,(const char *)619);
		p[405] = GetProcAddress(hL,(const char *)608);
		p[406] = GetProcAddress(hL,(const char *)312);
		p[407] = GetProcAddress(hL,(const char *)313);
		p[408] = GetProcAddress(hL,(const char *)314);
		p[409] = GetProcAddress(hL,(const char *)315);
		p[410] = GetProcAddress(hL,(const char *)321);
		p[411] = GetProcAddress(hL,(const char *)323);
		p[412] = GetProcAddress(hL,(const char *)326);
		p[413] = GetProcAddress(hL,(const char *)325);
		p[414] = GetProcAddress(hL,(const char *)324);
		p[415] = GetProcAddress(hL,(const char *)477);
		p[416] = GetProcAddress(hL,(const char *)478);
		p[417] = GetProcAddress(hL,(const char *)473);
		p[418] = GetProcAddress(hL,(const char *)474);
		p[419] = GetProcAddress(hL,(const char *)480);
		p[420] = GetProcAddress(hL,(const char *)476);
		p[421] = GetProcAddress(hL,(const char *)472);
		p[422] = GetProcAddress(hL,(const char *)475);
		p[423] = GetProcAddress(hL,(const char *)479);
		p[424] = GetProcAddress(hL,(const char *)334);
		p[425] = GetProcAddress(hL,(const char *)332);
		p[426] = GetProcAddress(hL,(const char *)331);
		p[427] = GetProcAddress(hL,(const char *)335);
		p[428] = GetProcAddress(hL,(const char *)551);
		p[429] = GetProcAddress(hL,(const char *)552);
		p[430] = GetProcAddress(hL,(const char *)211);
		p[431] = GetProcAddress(hL,(const char *)212);
		p[432] = GetProcAddress(hL,(const char *)217);
		p[433] = GetProcAddress(hL,(const char *)223);
		p[434] = GetProcAddress(hL,(const char *)218);
		p[435] = GetProcAddress(hL,(const char *)220);
		p[436] = GetProcAddress(hL,(const char *)221);
		p[437] = GetProcAddress(hL,(const char *)202);
		p[438] = GetProcAddress(hL,(const char *)206);
		p[439] = GetProcAddress(hL,(const char *)214);
		p[440] = GetProcAddress(hL,(const char *)210);
		p[441] = GetProcAddress(hL,(const char *)201);
		p[442] = GetProcAddress(hL,(const char *)203);
		p[443] = GetProcAddress(hL,(const char *)213);
		p[444] = GetProcAddress(hL,(const char *)222);
		p[445] = GetProcAddress(hL,(const char *)215);
		p[446] = GetProcAddress(hL,(const char *)216);
		p[447] = GetProcAddress(hL,(const char *)219);
		p[448] = GetProcAddress(hL,(const char *)204);
		p[449] = GetProcAddress(hL,(const char *)205);
		p[450] = GetProcAddress(hL,(const char *)208);
		p[451] = GetProcAddress(hL,(const char *)209);
		p[452] = GetProcAddress(hL,(const char *)344);
		p[453] = GetProcAddress(hL,(const char *)345);
		p[454] = GetProcAddress(hL,(const char *)346);
		p[455] = GetProcAddress(hL,(const char *)347);
		p[456] = GetProcAddress(hL,(const char *)348);
		p[457] = GetProcAddress(hL,(const char *)349);
		p[458] = GetProcAddress(hL,(const char *)350);
		p[459] = GetProcAddress(hL,(const char *)353);
		p[460] = GetProcAddress(hL,(const char *)354);
		p[461] = GetProcAddress(hL,(const char *)355);
		p[462] = GetProcAddress(hL,(const char *)356);
		p[463] = GetProcAddress(hL,(const char *)357);
		p[464] = GetProcAddress(hL,(const char *)358);
		p[465] = GetProcAddress(hL,(const char *)359);
		p[466] = GetProcAddress(hL,(const char *)342);
		p[467] = GetProcAddress(hL,(const char *)343);
		p[468] = GetProcAddress(hL,(const char *)351);
		p[469] = GetProcAddress(hL,(const char *)352);
		p[470] = GetProcAddress(hL,(const char *)341);
		p[471] = GetProcAddress(hL,(const char *)566);
		p[472] = GetProcAddress(hL,(const char *)463);
		p[473] = GetProcAddress(hL,(const char *)563);
		p[474] = GetProcAddress(hL,(const char *)564);
		p[475] = GetProcAddress(hL,(const char *)464);
		p[476] = GetProcAddress(hL,(const char *)465);
		p[477] = GetProcAddress(hL,(const char *)565);
		p[478] = GetProcAddress(hL,(const char *)568);
		p[479] = GetProcAddress(hL,(const char *)468);
		p[480] = GetProcAddress(hL,(const char *)460);
		p[481] = GetProcAddress(hL,(const char *)471);
		p[482] = GetProcAddress(hL,(const char *)557);
		p[483] = GetProcAddress(hL,(const char *)555);
		p[484] = GetProcAddress(hL,(const char *)554);
		p[485] = GetProcAddress(hL,(const char *)558);
		p[486] = GetProcAddress(hL,(const char *)556);
		p[487] = GetProcAddress(hL,(const char *)559);
		p[488] = GetProcAddress(hL,(const char *)560);
		p[489] = GetProcAddress(hL,(const char *)498);
		p[490] = GetProcAddress(hL,(const char *)298);
		p[491] = GetProcAddress(hL,(const char *)150);
		p[492] = GetProcAddress(hL,(const char *)462);
		p[493] = GetProcAddress(hL,(const char *)469);
		p[494] = GetProcAddress(hL,(const char *)461);
		p[495] = GetProcAddress(hL,(const char *)562);
		p[496] = GetProcAddress(hL,(const char *)466);
		p[497] = GetProcAddress(hL,(const char *)470);
		p[498] = GetProcAddress(hL,(const char *)561);
		p[499] = GetProcAddress(hL,(const char *)567);
		p[500] = GetProcAddress(hL,(const char *)467);
		p[501] = GetProcAddress(hL,(const char *)377);
		p[502] = GetProcAddress(hL,(const char *)373);
		p[503] = GetProcAddress(hL,(const char *)374);
		p[504] = GetProcAddress(hL,(const char *)375);
		p[505] = GetProcAddress(hL,(const char *)376);
		p[506] = GetProcAddress(hL,(const char *)378);
		p[507] = GetProcAddress(hL,(const char *)372);
		p[508] = GetProcAddress(hL,(const char *)295);
		p[509] = GetProcAddress(hL,(const char *)260);
		p[510] = GetProcAddress(hL,(const char *)263);
		p[511] = GetProcAddress(hL,(const char *)286);
		p[512] = GetProcAddress(hL,(const char *)284);
		p[513] = GetProcAddress(hL,(const char *)285);
		p[514] = GetProcAddress(hL,(const char *)274);
		p[515] = GetProcAddress(hL,(const char *)272);
		p[516] = GetProcAddress(hL,(const char *)294);
		p[517] = GetProcAddress(hL,(const char *)278);
		p[518] = GetProcAddress(hL,(const char *)280);
		p[519] = GetProcAddress(hL,(const char *)299);
		p[520] = GetProcAddress(hL,(const char *)151);
		p[521] = GetProcAddress(hL,(const char *)277);
		p[522] = GetProcAddress(hL,(const char *)273);
		p[523] = GetProcAddress(hL,(const char *)264);
		p[524] = GetProcAddress(hL,(const char *)276);
		p[525] = GetProcAddress(hL,(const char *)275);
		p[526] = GetProcAddress(hL,(const char *)297);
		p[527] = GetProcAddress(hL,(const char *)296);
		p[528] = GetProcAddress(hL,(const char *)265);
		p[529] = GetProcAddress(hL,(const char *)270);
		p[530] = GetProcAddress(hL,(const char *)271);
		p[531] = GetProcAddress(hL,(const char *)251);
		p[532] = GetProcAddress(hL,(const char *)258);
		p[533] = GetProcAddress(hL,(const char *)259);
		p[534] = GetProcAddress(hL,(const char *)261);
		p[535] = GetProcAddress(hL,(const char *)289);
		p[536] = GetProcAddress(hL,(const char *)288);
		p[537] = GetProcAddress(hL,(const char *)300);
		p[538] = GetProcAddress(hL,(const char *)268);
		p[539] = GetProcAddress(hL,(const char *)253);
		p[540] = GetProcAddress(hL,(const char *)267);
		p[541] = GetProcAddress(hL,(const char *)252);
		p[542] = GetProcAddress(hL,(const char *)256);
		p[543] = GetProcAddress(hL,(const char *)262);
		p[544] = GetProcAddress(hL,(const char *)283);
		p[545] = GetProcAddress(hL,(const char *)290);
		p[546] = GetProcAddress(hL,(const char *)257);
		p[547] = GetProcAddress(hL,(const char *)282);
		p[548] = GetProcAddress(hL,(const char *)291);
		p[549] = GetProcAddress(hL,(const char *)292);
		p[550] = GetProcAddress(hL,(const char *)269);
		p[551] = GetProcAddress(hL,(const char *)287);
		p[552] = GetProcAddress(hL,(const char *)255);
		p[553] = GetProcAddress(hL,(const char *)279);
		p[554] = GetProcAddress(hL,(const char *)281);
		p[555] = GetProcAddress(hL,(const char *)254);
		p[556] = GetProcAddress(hL,(const char *)266);
		p[557] = GetProcAddress(hL,(const char *)293);
		p[558] = GetProcAddress(hL,"SFile::EnableHash");
		p[559] = GetProcAddress(hL,"SFile::Unload");
		p[560] = GetProcAddress(hL,"SFile::GetActualFileName");
		p[561] = GetProcAddress(hL,"SFile::GetFileSize");
		p[562] = GetProcAddress(hL,"SFile::GetBasePath");
		p[563] = GetProcAddress(hL,"SFile::SetBasePath");
		p[564] = GetProcAddress(hL,"SFile::SetFilePointer");
		p[565] = GetProcAddress(hL,"SFile::ResetOverlapped");
		p[566] = GetProcAddress(hL,"SFile::WaitOverlapped");
		p[567] = GetProcAddress(hL,"SFile::PollOverlapped");
		p[568] = GetProcAddress(hL,"SFile::Close");
		p[569] = GetProcAddress(hL,"SFile::CreateOverlapped");
		p[570] = GetProcAddress(hL,"SFile::DestroyOverlapped");
		p[571] = GetProcAddress(hL,"SFile::Read");
		p[572] = GetProcAddress(hL,"SFile::Load");
		p[573] = GetProcAddress(hL,"SFile::FileExists");
		p[574] = GetProcAddress(hL,"SFile::Open");
		p[575] = GetProcAddress(hL,"SFile::LoadFile");
		p[576] = GetProcAddress(hL,(const char *)381);
		p[577] = GetProcAddress(hL,(const char *)393);
		p[578] = GetProcAddress(hL,(const char *)388);
		p[579] = GetProcAddress(hL,(const char *)389);
		p[580] = GetProcAddress(hL,(const char *)392);
		p[581] = GetProcAddress(hL,(const char *)385);
		p[582] = GetProcAddress(hL,(const char *)390);
		p[583] = GetProcAddress(hL,(const char *)391);
		p[584] = GetProcAddress(hL,(const char *)382);
		p[585] = GetProcAddress(hL,(const char *)386);
		p[586] = GetProcAddress(hL,(const char *)387);
		p[587] = GetProcAddress(hL,(const char *)383);
		p[588] = GetProcAddress(hL,"SInterlockedIncrement");
		p[589] = GetProcAddress(hL,"SInterlockedDecrement");
		p[590] = GetProcAddress(hL,"SInterlockedExchange");
		p[591] = GetProcAddress(hL,"SInterlockedRead");
		p[592] = GetProcAddress(hL,"SInterlockedExchange");
		p[593] = GetProcAddress(hL,"SInterlockedCompareExchange");
		p[594] = GetProcAddress(hL,"SInterlockedCompareExchangePointer");
		p[595] = GetProcAddress(hL,"SCritSect::SCritSect");
		p[596] = GetProcAddress(hL,"SCritSect::~SCritSect");
		p[597] = GetProcAddress(hL,"SCritSect::Enter");
		p[598] = GetProcAddress(hL,"SCritSect::Leave");
		p[599] = GetProcAddress(hL,"SSyncObject::SSyncObject");
		p[600] = GetProcAddress(hL,"SSyncObject::Wait");
		p[601] = GetProcAddress(hL,"WaitMultiplePtr");
		p[602] = GetProcAddress(hL,"SEvent::Set");
		p[603] = GetProcAddress(hL,"SEvent::Reset");
		p[604] = GetProcAddress(hL,"SThread::Create");
		p[605] = GetProcAddress(hL,"CSRWLock::CSRWLock");
		p[606] = GetProcAddress(hL,"CSRWLock::Leave");
		p[607] = GetProcAddress(hL,"SSyncObject::~SSyncObject");
		p[608] = GetProcAddress(hL,"SEvent::SEvent");
		p[609] = GetProcAddress(hL,"CDebugSCritSect::Enter");
		p[610] = GetProcAddress(hL,"CDebugSCritSect::Leave");
		p[611] = GetProcAddress(hL,"CDebugSRWLock::Leave");
		p[612] = GetProcAddress(hL,"CDebugSCritSect::CDebugSCritSect");
		p[613] = GetProcAddress(hL,"CDebugSCritSect::~CDebugSCritSect");
		p[614] = GetProcAddress(hL,"CSRWLock::~CSRWLock");
		p[615] = GetProcAddress(hL,"CDebugSRWLock::CDebugSRWLock");
		p[616] = GetProcAddress(hL,"CDebugSRWLock::~CDebugSRWLock");
		p[617] = GetProcAddress(hL,"CSRWLock::Enter");
		p[618] = GetProcAddress(hL,"CDebugSRWLock::Enter");
		p[619] = GetProcAddress(hL,(const char *)541);
		p[620] = GetProcAddress(hL,(const char *)542);
		p[621] = GetProcAddress(hL,(const char *)544);
		p[622] = GetProcAddress(hL,(const char *)545);
		p[623] = GetProcAddress(hL,(const char *)546);
		p[624] = GetProcAddress(hL,(const char *)586);
		p[625] = GetProcAddress(hL,(const char *)587);
		p[626] = GetProcAddress(hL,(const char *)547);
		p[627] = GetProcAddress(hL,(const char *)549);
		p[628] = GetProcAddress(hL,(const char *)585);
		p[629] = GetProcAddress(hL,(const char *)550);
		p[630] = GetProcAddress(hL,(const char *)543);
		p[631] = GetProcAddress(hL,(const char *)553);
		p[632] = GetProcAddress(hL,(const char *)548);
		p[633] = GetProcAddress(hL,(const char *)481);
		p[634] = GetProcAddress(hL,(const char *)491);
		p[635] = GetProcAddress(hL,(const char *)482);
		p[636] = GetProcAddress(hL,(const char *)403);
		p[637] = GetProcAddress(hL,(const char *)406);
		p[638] = GetProcAddress(hL,(const char *)483);
		p[639] = GetProcAddress(hL,(const char *)484);
		p[640] = GetProcAddress(hL,(const char *)404);
		p[641] = GetProcAddress(hL,(const char *)486);
		p[642] = GetProcAddress(hL,(const char *)488);
		p[643] = GetProcAddress(hL,(const char *)490);
		p[644] = GetProcAddress(hL,(const char *)496);
		p[645] = GetProcAddress(hL,(const char *)497);
		p[646] = GetProcAddress(hL,(const char *)487);
		p[647] = GetProcAddress(hL,(const char *)401);
		p[648] = GetProcAddress(hL,(const char *)485);
		p[649] = GetProcAddress(hL,(const char *)489);
		p[650] = GetProcAddress(hL,(const char *)405);
		p[651] = GetProcAddress(hL,(const char *)511);
		p[652] = GetProcAddress(hL,(const char *)413);
		p[653] = GetProcAddress(hL,(const char *)518);
		p[654] = GetProcAddress(hL,(const char *)583);
		p[655] = GetProcAddress(hL,(const char *)418);
		p[656] = GetProcAddress(hL,(const char *)419);
		p[657] = GetProcAddress(hL,(const char *)517);
		p[658] = GetProcAddress(hL,(const char *)582);
		p[659] = GetProcAddress(hL,(const char *)412);
		p[660] = GetProcAddress(hL,(const char *)414);
		p[661] = GetProcAddress(hL,(const char *)420);
		p[662] = GetProcAddress(hL,(const char *)415);
		p[663] = GetProcAddress(hL,(const char *)416);
		p[664] = GetProcAddress(hL,(const char *)417);
		p[665] = GetProcAddress(hL,(const char *)512);
		p[666] = GetProcAddress(hL,(const char *)519);
		p[667] = GetProcAddress(hL,(const char *)513);
		p[668] = GetProcAddress(hL,(const char *)514);
		p[669] = GetProcAddress(hL,(const char *)515);
		p[670] = GetProcAddress(hL,(const char *)516);
		p[671] = GetProcAddress(hL,(const char *)123);
		p[672] = GetProcAddress(hL,(const char *)129);
		p[673] = GetProcAddress(hL,(const char *)131);
		p[674] = GetProcAddress(hL,(const char *)140);
		p[675] = GetProcAddress(hL,(const char *)103);
		p[676] = GetProcAddress(hL,(const char *)104);
		p[677] = GetProcAddress(hL,(const char *)133);
		p[678] = GetProcAddress(hL,(const char *)107);
		p[679] = GetProcAddress(hL,(const char *)111);
		p[680] = GetProcAddress(hL,(const char *)114);
		p[681] = GetProcAddress(hL,(const char *)116);
		p[682] = GetProcAddress(hL,(const char *)120);
		p[683] = GetProcAddress(hL,(const char *)125);
		p[684] = GetProcAddress(hL,(const char *)108);
		p[685] = GetProcAddress(hL,(const char *)109);
		p[686] = GetProcAddress(hL,(const char *)112);
		p[687] = GetProcAddress(hL,(const char *)113);
		p[688] = GetProcAddress(hL,(const char *)124);
		p[689] = GetProcAddress(hL,(const char *)139);
		p[690] = GetProcAddress(hL,(const char *)105);
		p[691] = GetProcAddress(hL,(const char *)106);
		p[692] = GetProcAddress(hL,(const char *)115);
		p[693] = GetProcAddress(hL,(const char *)135);
		p[694] = GetProcAddress(hL,(const char *)127);
		p[695] = GetProcAddress(hL,(const char *)134);
		p[696] = GetProcAddress(hL,(const char *)128);
		p[697] = GetProcAddress(hL,(const char *)130);
		p[698] = GetProcAddress(hL,(const char *)137);
		p[699] = GetProcAddress(hL,(const char *)110);
		p[700] = GetProcAddress(hL,(const char *)136);
		p[701] = GetProcAddress(hL,(const char *)121);
		p[702] = GetProcAddress(hL,(const char *)122);
		p[703] = GetProcAddress(hL,(const char *)117);
		p[704] = GetProcAddress(hL,(const char *)119);
		p[705] = GetProcAddress(hL,(const char *)138);
		p[706] = GetProcAddress(hL,(const char *)102);
		p[707] = GetProcAddress(hL,(const char *)118);
		p[708] = GetProcAddress(hL,(const char *)126);
		p[709] = GetProcAddress(hL,(const char *)101);
		p[710] = GetProcAddress(hL,(const char *)303);
		p[711] = GetProcAddress(hL,(const char *)304);
		p[712] = GetProcAddress(hL,(const char *)427);
		p[713] = GetProcAddress(hL,(const char *)428);
		p[714] = GetProcAddress(hL,(const char *)584);
		p[715] = GetProcAddress(hL,(const char *)421);
		p[716] = GetProcAddress(hL,(const char *)422);
		p[717] = GetProcAddress(hL,(const char *)423);
		p[718] = GetProcAddress(hL,(const char *)424);
		p[719] = GetProcAddress(hL,(const char *)425);
		p[720] = GetProcAddress(hL,(const char *)426);
		p[721] = GetProcAddress(hL,(const char *)429);
		p[722] = GetProcAddress(hL,(const char *)430);
		p[723] = GetProcAddress(hL,(const char *)521);
		p[724] = GetProcAddress(hL,(const char *)534);
		p[725] = GetProcAddress(hL,(const char *)523);
		p[726] = GetProcAddress(hL,(const char *)537);
		p[727] = GetProcAddress(hL,(const char *)530);
		p[728] = GetProcAddress(hL,(const char *)535);
		p[729] = GetProcAddress(hL,(const char *)528);
		p[730] = GetProcAddress(hL,(const char *)536);
		p[731] = GetProcAddress(hL,(const char *)529);
		p[732] = GetProcAddress(hL,(const char *)538);
		p[733] = GetProcAddress(hL,(const char *)531);
		p[734] = GetProcAddress(hL,(const char *)539);
		p[735] = GetProcAddress(hL,(const char *)532);
		p[736] = GetProcAddress(hL,(const char *)540);
		p[737] = GetProcAddress(hL,(const char *)533);
		p[738] = GetProcAddress(hL,(const char *)525);
		p[739] = GetProcAddress(hL,(const char *)524);
		p[740] = GetProcAddress(hL,(const char *)527);
		p[741] = GetProcAddress(hL,(const char *)653);
		p[742] = GetProcAddress(hL,(const char *)650);
		p[743] = GetProcAddress(hL,(const char *)649);
		p[744] = GetProcAddress(hL,(const char *)652);
		p[745] = GetProcAddress(hL,(const char *)651);
		p[746] = GetProcAddress(hL,(const char *)648);
		p[747] = GetProcAddress(hL,(const char *)569);
		p[748] = GetProcAddress(hL,(const char *)571);
		p[749] = GetProcAddress(hL,(const char *)572);
		p[750] = GetProcAddress(hL,(const char *)570);
		p[751] = GetProcAddress(hL,(const char *)508);
		p[752] = GetProcAddress(hL,(const char *)509);
		p[753] = GetProcAddress(hL,(const char *)501);
		p[754] = GetProcAddress(hL,(const char *)506);
		p[755] = GetProcAddress(hL,(const char *)598);
		p[756] = GetProcAddress(hL,(const char *)503);
		p[757] = GetProcAddress(hL,(const char *)578);
		p[758] = GetProcAddress(hL,(const char *)581);
		p[759] = GetProcAddress(hL,(const char *)575);
		p[760] = GetProcAddress(hL,(const char *)576);
		p[761] = GetProcAddress(hL,(const char *)504);
		p[762] = GetProcAddress(hL,(const char *)502);
		p[763] = GetProcAddress(hL,(const char *)580);
		p[764] = GetProcAddress(hL,(const char *)590);
		p[765] = GetProcAddress(hL,(const char *)510);
		p[766] = GetProcAddress(hL,(const char *)579);
		p[767] = GetProcAddress(hL,(const char *)588);
		p[768] = GetProcAddress(hL,(const char *)596);
		p[769] = GetProcAddress(hL,(const char *)597);
		p[770] = GetProcAddress(hL,(const char *)589);
		p[771] = GetProcAddress(hL,(const char *)592);
		p[772] = GetProcAddress(hL,(const char *)591);
		p[773] = GetProcAddress(hL,(const char *)507);
		p[774] = GetProcAddress(hL,(const char *)573);
		p[775] = GetProcAddress(hL,(const char *)574);
		p[776] = GetProcAddress(hL,(const char *)577);
		p[777] = GetProcAddress(hL,"SGetCurrentThreadId");
		p[778] = GetProcAddress(hL,"SGetCurrentThreadPriority");
		p[779] = GetProcAddress(hL,"SSetCurrentThreadPriority");
		p[780] = GetProcAddress(hL,"SCreateThread");
		p[781] = GetProcAddress(hL,(const char *)301);
		p[782] = GetProcAddress(hL,(const char *)302);
		p[783] = GetProcAddress(hL,(const char *)399);
		p[784] = GetProcAddress(hL,(const char *)431);
		p[785] = GetProcAddress(hL,(const char *)432);
		p[786] = GetProcAddress(hL,(const char *)442);
		p[787] = GetProcAddress(hL,(const char *)440);
		p[788] = GetProcAddress(hL,(const char *)441);
		p[789] = GetProcAddress(hL,(const char *)445);
		p[790] = GetProcAddress(hL,(const char *)433);
		p[791] = GetProcAddress(hL,(const char *)446);
		p[792] = GetProcAddress(hL,(const char *)444);
		p[793] = GetProcAddress(hL,(const char *)436);
		p[794] = GetProcAddress(hL,(const char *)438);
		p[795] = GetProcAddress(hL,(const char *)437);
		p[796] = GetProcAddress(hL,(const char *)443);
		p[797] = GetProcAddress(hL,(const char *)447);
		p[798] = GetProcAddress(hL,(const char *)439);
		p[799] = GetProcAddress(hL,(const char *)434);
		p[800] = GetProcAddress(hL,(const char *)901);
		p[801] = GetProcAddress(hL,(const char *)902);
		p[802] = GetProcAddress(hL,(const char *)903);
		p[803] = GetProcAddress(hL,(const char *)904);
		p[804] = GetProcAddress(hL,(const char *)905);
		p[805] = GetProcAddress(hL,(const char *)906);
		p[806] = GetProcAddress(hL,(const char *)907);
		p[807] = GetProcAddress(hL,(const char *)908);
		p[808] = GetProcAddress(hL,(const char *)909);
		p[809] = GetProcAddress(hL,(const char *)910);
		p[810] = GetProcAddress(hL,(const char *)911);
		p[811] = GetProcAddress(hL,(const char *)912);
		p[812] = GetProcAddress(hL,(const char *)913);
		p[813] = GetProcAddress(hL,(const char *)914);
	}
	if (reason == DLL_PROCESS_DETACH)
		FreeLibrary(hL);
	return TRUE;
}

extern "C" __declspec(naked) void Proxy_Ordinal448()
{
 __asm
 {
     jmp p[0*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal753()
{
 __asm
 {
     jmp p[1*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal752()
{
 __asm
 {
     jmp p[2*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal751()
{
 __asm
 {
     jmp p[3*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal750()
{
 __asm
 {
     jmp p[4*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal749()
{
 __asm
 {
     jmp p[5*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal748()
{
 __asm
 {
     jmp p[6*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal747()
{
 __asm
 {
     jmp p[7*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal746()
{
 __asm
 {
     jmp p[8*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal745()
{
 __asm
 {
     jmp p[9*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal744()
{
 __asm
 {
     jmp p[10*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal743()
{
 __asm
 {
     jmp p[11*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal742()
{
 __asm
 {
     jmp p[12*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal741()
{
 __asm
 {
     jmp p[13*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal740()
{
 __asm
 {
     jmp p[14*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal739()
{
 __asm
 {
     jmp p[15*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal738()
{
 __asm
 {
     jmp p[16*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal737()
{
 __asm
 {
     jmp p[17*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal736()
{
 __asm
 {
     jmp p[18*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal735()
{
 __asm
 {
     jmp p[19*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal734()
{
 __asm
 {
     jmp p[20*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal733()
{
 __asm
 {
     jmp p[21*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal732()
{
 __asm
 {
     jmp p[22*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal731()
{
 __asm
 {
     jmp p[23*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal730()
{
 __asm
 {
     jmp p[24*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal729()
{
 __asm
 {
     jmp p[25*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal728()
{
 __asm
 {
     jmp p[26*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal727()
{
 __asm
 {
     jmp p[27*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal726()
{
 __asm
 {
     jmp p[28*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal725()
{
 __asm
 {
     jmp p[29*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal724()
{
 __asm
 {
     jmp p[30*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal723()
{
 __asm
 {
     jmp p[31*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal722()
{
 __asm
 {
     jmp p[32*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal721()
{
 __asm
 {
     jmp p[33*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal720()
{
 __asm
 {
     jmp p[34*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal719()
{
 __asm
 {
     jmp p[35*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal718()
{
 __asm
 {
     jmp p[36*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal717()
{
 __asm
 {
     jmp p[37*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal716()
{
 __asm
 {
     jmp p[38*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal715()
{
 __asm
 {
     jmp p[39*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal714()
{
 __asm
 {
     jmp p[40*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal713()
{
 __asm
 {
     jmp p[41*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal900()
{
 __asm
 {
     jmp p[42*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal899()
{
 __asm
 {
     jmp p[43*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal898()
{
 __asm
 {
     jmp p[44*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal897()
{
 __asm
 {
     jmp p[45*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal896()
{
 __asm
 {
     jmp p[46*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal895()
{
 __asm
 {
     jmp p[47*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal894()
{
 __asm
 {
     jmp p[48*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal893()
{
 __asm
 {
     jmp p[49*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal892()
{
 __asm
 {
     jmp p[50*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal712()
{
 __asm
 {
     jmp p[51*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal711()
{
 __asm
 {
     jmp p[52*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal195()
{
 __asm
 {
     jmp p[53*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal196()
{
 __asm
 {
     jmp p[54*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal197()
{
 __asm
 {
     jmp p[55*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal198()
{
 __asm
 {
     jmp p[56*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal199()
{
 __asm
 {
     jmp p[57*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal200()
{
 __asm
 {
     jmp p[58*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal710()
{
 __asm
 {
     jmp p[59*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal709()
{
 __asm
 {
     jmp p[60*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal708()
{
 __asm
 {
     jmp p[61*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal707()
{
 __asm
 {
     jmp p[62*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal706()
{
 __asm
 {
     jmp p[63*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal705()
{
 __asm
 {
     jmp p[64*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal207()
{
 __asm
 {
     jmp p[65*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal704()
{
 __asm
 {
     jmp p[66*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal703()
{
 __asm
 {
     jmp p[67*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal702()
{
 __asm
 {
     jmp p[68*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal701()
{
 __asm
 {
     jmp p[69*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal700()
{
 __asm
 {
     jmp p[70*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal699()
{
 __asm
 {
     jmp p[71*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal698()
{
 __asm
 {
     jmp p[72*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal697()
{
 __asm
 {
     jmp p[73*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal696()
{
 __asm
 {
     jmp p[74*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal695()
{
 __asm
 {
     jmp p[75*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal694()
{
 __asm
 {
     jmp p[76*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal693()
{
 __asm
 {
     jmp p[77*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal692()
{
 __asm
 {
     jmp p[78*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal691()
{
 __asm
 {
     jmp p[79*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal690()
{
 __asm
 {
     jmp p[80*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal689()
{
 __asm
 {
     jmp p[81*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal224()
{
 __asm
 {
     jmp p[82*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal225()
{
 __asm
 {
     jmp p[83*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal226()
{
 __asm
 {
     jmp p[84*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal227()
{
 __asm
 {
     jmp p[85*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal228()
{
 __asm
 {
     jmp p[86*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal229()
{
 __asm
 {
     jmp p[87*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal230()
{
 __asm
 {
     jmp p[88*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal231()
{
 __asm
 {
     jmp p[89*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal232()
{
 __asm
 {
     jmp p[90*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal233()
{
 __asm
 {
     jmp p[91*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal234()
{
 __asm
 {
     jmp p[92*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal235()
{
 __asm
 {
     jmp p[93*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal236()
{
 __asm
 {
     jmp p[94*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal237()
{
 __asm
 {
     jmp p[95*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal238()
{
 __asm
 {
     jmp p[96*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal239()
{
 __asm
 {
     jmp p[97*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal240()
{
 __asm
 {
     jmp p[98*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal241()
{
 __asm
 {
     jmp p[99*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal242()
{
 __asm
 {
     jmp p[100*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal243()
{
 __asm
 {
     jmp p[101*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal244()
{
 __asm
 {
     jmp p[102*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal245()
{
 __asm
 {
     jmp p[103*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal246()
{
 __asm
 {
     jmp p[104*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal247()
{
 __asm
 {
     jmp p[105*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal248()
{
 __asm
 {
     jmp p[106*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal249()
{
 __asm
 {
     jmp p[107*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal250()
{
 __asm
 {
     jmp p[108*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal688()
{
 __asm
 {
     jmp p[109*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal687()
{
 __asm
 {
     jmp p[110*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal686()
{
 __asm
 {
     jmp p[111*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal685()
{
 __asm
 {
     jmp p[112*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal684()
{
 __asm
 {
     jmp p[113*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal683()
{
 __asm
 {
     jmp p[114*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal682()
{
 __asm
 {
     jmp p[115*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal681()
{
 __asm
 {
     jmp p[116*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal680()
{
 __asm
 {
     jmp p[117*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal679()
{
 __asm
 {
     jmp p[118*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal678()
{
 __asm
 {
     jmp p[119*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal677()
{
 __asm
 {
     jmp p[120*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal676()
{
 __asm
 {
     jmp p[121*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal675()
{
 __asm
 {
     jmp p[122*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal674()
{
 __asm
 {
     jmp p[123*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal673()
{
 __asm
 {
     jmp p[124*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal672()
{
 __asm
 {
     jmp p[125*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal671()
{
 __asm
 {
     jmp p[126*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal670()
{
 __asm
 {
     jmp p[127*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal669()
{
 __asm
 {
     jmp p[128*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal668()
{
 __asm
 {
     jmp p[129*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal667()
{
 __asm
 {
     jmp p[130*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal666()
{
 __asm
 {
     jmp p[131*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal665()
{
 __asm
 {
     jmp p[132*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal664()
{
 __asm
 {
     jmp p[133*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal663()
{
 __asm
 {
     jmp p[134*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal662()
{
 __asm
 {
     jmp p[135*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal661()
{
 __asm
 {
     jmp p[136*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal660()
{
 __asm
 {
     jmp p[137*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal659()
{
 __asm
 {
     jmp p[138*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal658()
{
 __asm
 {
     jmp p[139*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal657()
{
 __asm
 {
     jmp p[140*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal656()
{
 __asm
 {
     jmp p[141*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal655()
{
 __asm
 {
     jmp p[142*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal755()
{
 __asm
 {
     jmp p[143*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal756()
{
 __asm
 {
     jmp p[144*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal757()
{
 __asm
 {
     jmp p[145*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal758()
{
 __asm
 {
     jmp p[146*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal759()
{
 __asm
 {
     jmp p[147*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal760()
{
 __asm
 {
     jmp p[148*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal600()
{
 __asm
 {
     jmp p[149*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal599()
{
 __asm
 {
     jmp p[150*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal761()
{
 __asm
 {
     jmp p[151*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal762()
{
 __asm
 {
     jmp p[152*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal763()
{
 __asm
 {
     jmp p[153*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal764()
{
 __asm
 {
     jmp p[154*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal765()
{
 __asm
 {
     jmp p[155*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal766()
{
 __asm
 {
     jmp p[156*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal767()
{
 __asm
 {
     jmp p[157*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal768()
{
 __asm
 {
     jmp p[158*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal891()
{
 __asm
 {
     jmp p[159*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal890()
{
 __asm
 {
     jmp p[160*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal889()
{
 __asm
 {
     jmp p[161*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal888()
{
 __asm
 {
     jmp p[162*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal305()
{
 __asm
 {
     jmp p[163*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal306()
{
 __asm
 {
     jmp p[164*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal307()
{
 __asm
 {
     jmp p[165*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal308()
{
 __asm
 {
     jmp p[166*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal309()
{
 __asm
 {
     jmp p[167*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal310()
{
 __asm
 {
     jmp p[168*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal311()
{
 __asm
 {
     jmp p[169*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal769()
{
 __asm
 {
     jmp p[170*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal770()
{
 __asm
 {
     jmp p[171*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal771()
{
 __asm
 {
     jmp p[172*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal772()
{
 __asm
 {
     jmp p[173*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal316()
{
 __asm
 {
     jmp p[174*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal317()
{
 __asm
 {
     jmp p[175*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal318()
{
 __asm
 {
     jmp p[176*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal319()
{
 __asm
 {
     jmp p[177*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal320()
{
 __asm
 {
     jmp p[178*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal773()
{
 __asm
 {
     jmp p[179*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal322()
{
 __asm
 {
     jmp p[180*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal774()
{
 __asm
 {
     jmp p[181*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal775()
{
 __asm
 {
     jmp p[182*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal776()
{
 __asm
 {
     jmp p[183*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal777()
{
 __asm
 {
     jmp p[184*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal327()
{
 __asm
 {
     jmp p[185*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal328()
{
 __asm
 {
     jmp p[186*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal329()
{
 __asm
 {
     jmp p[187*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal330()
{
 __asm
 {
     jmp p[188*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal778()
{
 __asm
 {
     jmp p[189*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal779()
{
 __asm
 {
     jmp p[190*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal333()
{
 __asm
 {
     jmp p[191*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal780()
{
 __asm
 {
     jmp p[192*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal781()
{
 __asm
 {
     jmp p[193*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal336()
{
 __asm
 {
     jmp p[194*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal337()
{
 __asm
 {
     jmp p[195*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal338()
{
 __asm
 {
     jmp p[196*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal339()
{
 __asm
 {
     jmp p[197*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal340()
{
 __asm
 {
     jmp p[198*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal782()
{
 __asm
 {
     jmp p[199*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal783()
{
 __asm
 {
     jmp p[200*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal784()
{
 __asm
 {
     jmp p[201*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal785()
{
 __asm
 {
     jmp p[202*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal786()
{
 __asm
 {
     jmp p[203*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal787()
{
 __asm
 {
     jmp p[204*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal788()
{
 __asm
 {
     jmp p[205*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal789()
{
 __asm
 {
     jmp p[206*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal790()
{
 __asm
 {
     jmp p[207*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal791()
{
 __asm
 {
     jmp p[208*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal792()
{
 __asm
 {
     jmp p[209*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal793()
{
 __asm
 {
     jmp p[210*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal794()
{
 __asm
 {
     jmp p[211*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal795()
{
 __asm
 {
     jmp p[212*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal796()
{
 __asm
 {
     jmp p[213*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal797()
{
 __asm
 {
     jmp p[214*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal798()
{
 __asm
 {
     jmp p[215*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal799()
{
 __asm
 {
     jmp p[216*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal800()
{
 __asm
 {
     jmp p[217*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal360()
{
 __asm
 {
     jmp p[218*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal361()
{
 __asm
 {
     jmp p[219*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal362()
{
 __asm
 {
     jmp p[220*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal363()
{
 __asm
 {
     jmp p[221*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal364()
{
 __asm
 {
     jmp p[222*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal365()
{
 __asm
 {
     jmp p[223*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal366()
{
 __asm
 {
     jmp p[224*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal367()
{
 __asm
 {
     jmp p[225*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal368()
{
 __asm
 {
     jmp p[226*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal369()
{
 __asm
 {
     jmp p[227*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal370()
{
 __asm
 {
     jmp p[228*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal371()
{
 __asm
 {
     jmp p[229*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal801()
{
 __asm
 {
     jmp p[230*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal802()
{
 __asm
 {
     jmp p[231*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal803()
{
 __asm
 {
     jmp p[232*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal804()
{
 __asm
 {
     jmp p[233*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal805()
{
 __asm
 {
     jmp p[234*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal806()
{
 __asm
 {
     jmp p[235*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal807()
{
 __asm
 {
     jmp p[236*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal379()
{
 __asm
 {
     jmp p[237*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal380()
{
 __asm
 {
     jmp p[238*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal808()
{
 __asm
 {
     jmp p[239*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal809()
{
 __asm
 {
     jmp p[240*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal810()
{
 __asm
 {
     jmp p[241*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal384()
{
 __asm
 {
     jmp p[242*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal811()
{
 __asm
 {
     jmp p[243*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal526()
{
 __asm
 {
     jmp p[244*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal812()
{
 __asm
 {
     jmp p[245*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal813()
{
 __asm
 {
     jmp p[246*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal814()
{
 __asm
 {
     jmp p[247*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal522()
{
 __asm
 {
     jmp p[248*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal815()
{
 __asm
 {
     jmp p[249*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal520()
{
 __asm
 {
     jmp p[250*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal816()
{
 __asm
 {
     jmp p[251*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal394()
{
 __asm
 {
     jmp p[252*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal395()
{
 __asm
 {
     jmp p[253*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal396()
{
 __asm
 {
     jmp p[254*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal397()
{
 __asm
 {
     jmp p[255*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal398()
{
 __asm
 {
     jmp p[256*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal887()
{
 __asm
 {
     jmp p[257*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal400()
{
 __asm
 {
     jmp p[258*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal886()
{
 __asm
 {
     jmp p[259*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal402()
{
 __asm
 {
     jmp p[260*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal885()
{
 __asm
 {
     jmp p[261*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal884()
{
 __asm
 {
     jmp p[262*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal883()
{
 __asm
 {
     jmp p[263*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal882()
{
 __asm
 {
     jmp p[264*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal407()
{
 __asm
 {
     jmp p[265*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal408()
{
 __asm
 {
     jmp p[266*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal409()
{
 __asm
 {
     jmp p[267*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal410()
{
 __asm
 {
     jmp p[268*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal411()
{
 __asm
 {
     jmp p[269*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal881()
{
 __asm
 {
     jmp p[270*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal880()
{
 __asm
 {
     jmp p[271*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal879()
{
 __asm
 {
     jmp p[272*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal878()
{
 __asm
 {
     jmp p[273*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal877()
{
 __asm
 {
     jmp p[274*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal876()
{
 __asm
 {
     jmp p[275*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal875()
{
 __asm
 {
     jmp p[276*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal874()
{
 __asm
 {
     jmp p[277*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal873()
{
 __asm
 {
     jmp p[278*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal872()
{
 __asm
 {
     jmp p[279*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal871()
{
 __asm
 {
     jmp p[280*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal870()
{
 __asm
 {
     jmp p[281*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal869()
{
 __asm
 {
     jmp p[282*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal868()
{
 __asm
 {
     jmp p[283*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal867()
{
 __asm
 {
     jmp p[284*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal866()
{
 __asm
 {
     jmp p[285*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal865()
{
 __asm
 {
     jmp p[286*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal864()
{
 __asm
 {
     jmp p[287*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal863()
{
 __asm
 {
     jmp p[288*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal862()
{
 __asm
 {
     jmp p[289*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal861()
{
 __asm
 {
     jmp p[290*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal860()
{
 __asm
 {
     jmp p[291*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal859()
{
 __asm
 {
     jmp p[292*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal435()
{
 __asm
 {
     jmp p[293*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal858()
{
 __asm
 {
     jmp p[294*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal857()
{
 __asm
 {
     jmp p[295*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal856()
{
 __asm
 {
     jmp p[296*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal855()
{
 __asm
 {
     jmp p[297*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal854()
{
 __asm
 {
     jmp p[298*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal853()
{
 __asm
 {
     jmp p[299*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal852()
{
 __asm
 {
     jmp p[300*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal851()
{
 __asm
 {
     jmp p[301*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal850()
{
 __asm
 {
     jmp p[302*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal849()
{
 __asm
 {
     jmp p[303*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal848()
{
 __asm
 {
     jmp p[304*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal847()
{
 __asm
 {
     jmp p[305*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal754()
{
 __asm
 {
     jmp p[306*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal449()
{
 __asm
 {
     jmp p[307*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal450()
{
 __asm
 {
     jmp p[308*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal451()
{
 __asm
 {
     jmp p[309*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal452()
{
 __asm
 {
     jmp p[310*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal453()
{
 __asm
 {
     jmp p[311*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal454()
{
 __asm
 {
     jmp p[312*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal455()
{
 __asm
 {
     jmp p[313*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal456()
{
 __asm
 {
     jmp p[314*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal457()
{
 __asm
 {
     jmp p[315*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal458()
{
 __asm
 {
     jmp p[316*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal459()
{
 __asm
 {
     jmp p[317*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal817()
{
 __asm
 {
     jmp p[318*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal818()
{
 __asm
 {
     jmp p[319*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal819()
{
 __asm
 {
     jmp p[320*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal820()
{
 __asm
 {
     jmp p[321*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal821()
{
 __asm
 {
     jmp p[322*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal822()
{
 __asm
 {
     jmp p[323*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal823()
{
 __asm
 {
     jmp p[324*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal824()
{
 __asm
 {
     jmp p[325*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal825()
{
 __asm
 {
     jmp p[326*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal826()
{
 __asm
 {
     jmp p[327*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal827()
{
 __asm
 {
     jmp p[328*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal828()
{
 __asm
 {
     jmp p[329*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal829()
{
 __asm
 {
     jmp p[330*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal505()
{
 __asm
 {
     jmp p[331*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal830()
{
 __asm
 {
     jmp p[332*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal831()
{
 __asm
 {
     jmp p[333*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal832()
{
 __asm
 {
     jmp p[334*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal833()
{
 __asm
 {
     jmp p[335*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal500()
{
 __asm
 {
     jmp p[336*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal499()
{
 __asm
 {
     jmp p[337*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal834()
{
 __asm
 {
     jmp p[338*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal846()
{
 __asm
 {
     jmp p[339*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal845()
{
 __asm
 {
     jmp p[340*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal844()
{
 __asm
 {
     jmp p[341*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal843()
{
 __asm
 {
     jmp p[342*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal842()
{
 __asm
 {
     jmp p[343*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal841()
{
 __asm
 {
     jmp p[344*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal840()
{
 __asm
 {
     jmp p[345*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal839()
{
 __asm
 {
     jmp p[346*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal838()
{
 __asm
 {
     jmp p[347*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal837()
{
 __asm
 {
     jmp p[348*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal836()
{
 __asm
 {
     jmp p[349*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal492()
{
 __asm
 {
     jmp p[350*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal493()
{
 __asm
 {
     jmp p[351*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal494()
{
 __asm
 {
     jmp p[352*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal495()
{
 __asm
 {
     jmp p[353*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal835()
{
 __asm
 {
     jmp p[354*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal595()
{
 __asm
 {
     jmp p[355*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal593()
{
 __asm
 {
     jmp p[356*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal594()
{
 __asm
 {
     jmp p[357*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal603()
{
 __asm
 {
     jmp p[358*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal616()
{
 __asm
 {
     jmp p[359*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal646()
{
 __asm
 {
     jmp p[360*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal601()
{
 __asm
 {
     jmp p[361*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal602()
{
 __asm
 {
     jmp p[362*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal654()
{
 __asm
 {
     jmp p[363*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal605()
{
 __asm
 {
     jmp p[364*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal609()
{
 __asm
 {
     jmp p[365*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal610()
{
 __asm
 {
     jmp p[366*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal611()
{
 __asm
 {
     jmp p[367*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal612()
{
 __asm
 {
     jmp p[368*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal614()
{
 __asm
 {
     jmp p[369*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal617()
{
 __asm
 {
     jmp p[370*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal618()
{
 __asm
 {
     jmp p[371*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal620()
{
 __asm
 {
     jmp p[372*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal625()
{
 __asm
 {
     jmp p[373*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal626()
{
 __asm
 {
     jmp p[374*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal630()
{
 __asm
 {
     jmp p[375*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal631()
{
 __asm
 {
     jmp p[376*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal632()
{
 __asm
 {
     jmp p[377*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal633()
{
 __asm
 {
     jmp p[378*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal634()
{
 __asm
 {
     jmp p[379*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal636()
{
 __asm
 {
     jmp p[380*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal647()
{
 __asm
 {
     jmp p[381*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal604()
{
 __asm
 {
     jmp p[382*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal607()
{
 __asm
 {
     jmp p[383*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal613()
{
 __asm
 {
     jmp p[384*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal621()
{
 __asm
 {
     jmp p[385*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal624()
{
 __asm
 {
     jmp p[386*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal637()
{
 __asm
 {
     jmp p[387*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal638()
{
 __asm
 {
     jmp p[388*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal639()
{
 __asm
 {
     jmp p[389*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal640()
{
 __asm
 {
     jmp p[390*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal641()
{
 __asm
 {
     jmp p[391*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal642()
{
 __asm
 {
     jmp p[392*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal643()
{
 __asm
 {
     jmp p[393*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal644()
{
 __asm
 {
     jmp p[394*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal645()
{
 __asm
 {
     jmp p[395*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal606()
{
 __asm
 {
     jmp p[396*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal622()
{
 __asm
 {
     jmp p[397*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal623()
{
 __asm
 {
     jmp p[398*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal627()
{
 __asm
 {
     jmp p[399*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal629()
{
 __asm
 {
     jmp p[400*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal635()
{
 __asm
 {
     jmp p[401*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal615()
{
 __asm
 {
     jmp p[402*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal628()
{
 __asm
 {
     jmp p[403*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal619()
{
 __asm
 {
     jmp p[404*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal608()
{
 __asm
 {
     jmp p[405*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal312()
{
 __asm
 {
     jmp p[406*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal313()
{
 __asm
 {
     jmp p[407*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal314()
{
 __asm
 {
     jmp p[408*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal315()
{
 __asm
 {
     jmp p[409*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal321()
{
 __asm
 {
     jmp p[410*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal323()
{
 __asm
 {
     jmp p[411*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal326()
{
 __asm
 {
     jmp p[412*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal325()
{
 __asm
 {
     jmp p[413*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal324()
{
 __asm
 {
     jmp p[414*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal477()
{
 __asm
 {
     jmp p[415*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal478()
{
 __asm
 {
     jmp p[416*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal473()
{
 __asm
 {
     jmp p[417*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal474()
{
 __asm
 {
     jmp p[418*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal480()
{
 __asm
 {
     jmp p[419*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal476()
{
 __asm
 {
     jmp p[420*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal472()
{
 __asm
 {
     jmp p[421*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal475()
{
 __asm
 {
     jmp p[422*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal479()
{
 __asm
 {
     jmp p[423*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal334()
{
 __asm
 {
     jmp p[424*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal332()
{
 __asm
 {
     jmp p[425*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal331()
{
 __asm
 {
     jmp p[426*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal335()
{
 __asm
 {
     jmp p[427*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal551()
{
 __asm
 {
     jmp p[428*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal552()
{
 __asm
 {
     jmp p[429*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal211()
{
 __asm
 {
     jmp p[430*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal212()
{
 __asm
 {
     jmp p[431*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal217()
{
 __asm
 {
     jmp p[432*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal223()
{
 __asm
 {
     jmp p[433*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal218()
{
 __asm
 {
     jmp p[434*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal220()
{
 __asm
 {
     jmp p[435*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal221()
{
 __asm
 {
     jmp p[436*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal202()
{
 __asm
 {
     jmp p[437*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal206()
{
 __asm
 {
     jmp p[438*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal214()
{
 __asm
 {
     jmp p[439*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal210()
{
 __asm
 {
     jmp p[440*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal201()
{
 __asm
 {
     jmp p[441*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal203()
{
 __asm
 {
     jmp p[442*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal213()
{
 __asm
 {
     jmp p[443*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal222()
{
 __asm
 {
     jmp p[444*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal215()
{
 __asm
 {
     jmp p[445*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal216()
{
 __asm
 {
     jmp p[446*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal219()
{
 __asm
 {
     jmp p[447*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal204()
{
 __asm
 {
     jmp p[448*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal205()
{
 __asm
 {
     jmp p[449*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal208()
{
 __asm
 {
     jmp p[450*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal209()
{
 __asm
 {
     jmp p[451*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal344()
{
 __asm
 {
     jmp p[452*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal345()
{
 __asm
 {
     jmp p[453*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal346()
{
 __asm
 {
     jmp p[454*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal347()
{
 __asm
 {
     jmp p[455*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal348()
{
 __asm
 {
     jmp p[456*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal349()
{
 __asm
 {
     jmp p[457*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal350()
{
 __asm
 {
     jmp p[458*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal353()
{
 __asm
 {
     jmp p[459*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal354()
{
 __asm
 {
     jmp p[460*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal355()
{
 __asm
 {
     jmp p[461*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal356()
{
 __asm
 {
     jmp p[462*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal357()
{
 __asm
 {
     jmp p[463*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal358()
{
 __asm
 {
     jmp p[464*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal359()
{
 __asm
 {
     jmp p[465*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal342()
{
 __asm
 {
     jmp p[466*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal343()
{
 __asm
 {
     jmp p[467*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal351()
{
 __asm
 {
     jmp p[468*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal352()
{
 __asm
 {
     jmp p[469*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal341()
{
 __asm
 {
     jmp p[470*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal566()
{
 __asm
 {
     jmp p[471*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal463()
{
 __asm
 {
     jmp p[472*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal563()
{
 __asm
 {
     jmp p[473*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal564()
{
 __asm
 {
     jmp p[474*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal464()
{
 __asm
 {
     jmp p[475*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal465()
{
 __asm
 {
     jmp p[476*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal565()
{
 __asm
 {
     jmp p[477*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal568()
{
 __asm
 {
     jmp p[478*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal468()
{
 __asm
 {
     jmp p[479*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal460()
{
 __asm
 {
     jmp p[480*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal471()
{
 __asm
 {
     jmp p[481*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal557()
{
 __asm
 {
     jmp p[482*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal555()
{
 __asm
 {
     jmp p[483*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal554()
{
 __asm
 {
     jmp p[484*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal558()
{
 __asm
 {
     jmp p[485*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal556()
{
 __asm
 {
     jmp p[486*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal559()
{
 __asm
 {
     jmp p[487*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal560()
{
 __asm
 {
     jmp p[488*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal498()
{
 __asm
 {
     jmp p[489*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal298()
{
 __asm
 {
     jmp p[490*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal150()
{
 __asm
 {
     jmp p[491*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal462()
{
 __asm
 {
     jmp p[492*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal469()
{
 __asm
 {
     jmp p[493*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal461()
{
 __asm
 {
     jmp p[494*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal562()
{
 __asm
 {
     jmp p[495*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal466()
{
 __asm
 {
     jmp p[496*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal470()
{
 __asm
 {
     jmp p[497*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal561()
{
 __asm
 {
     jmp p[498*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal567()
{
 __asm
 {
     jmp p[499*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal467()
{
 __asm
 {
     jmp p[500*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal377()
{
 __asm
 {
     jmp p[501*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal373()
{
 __asm
 {
     jmp p[502*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal374()
{
 __asm
 {
     jmp p[503*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal375()
{
 __asm
 {
     jmp p[504*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal376()
{
 __asm
 {
     jmp p[505*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal378()
{
 __asm
 {
     jmp p[506*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal372()
{
 __asm
 {
     jmp p[507*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal295()
{
 __asm
 {
     jmp p[508*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal260()
{
 __asm
 {
     jmp p[509*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal263()
{
 __asm
 {
     jmp p[510*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal286()
{
 __asm
 {
     jmp p[511*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal284()
{
 __asm
 {
     jmp p[512*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal285()
{
 __asm
 {
     jmp p[513*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal274()
{
 __asm
 {
     jmp p[514*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal272()
{
 __asm
 {
     jmp p[515*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal294()
{
 __asm
 {
     jmp p[516*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal278()
{
 __asm
 {
     jmp p[517*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal280()
{
 __asm
 {
     jmp p[518*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal299()
{
 __asm
 {
     jmp p[519*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal151()
{
 __asm
 {
     jmp p[520*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal277()
{
 __asm
 {
     jmp p[521*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal273()
{
 __asm
 {
     jmp p[522*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal264()
{
 __asm
 {
     jmp p[523*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal276()
{
 __asm
 {
     jmp p[524*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal275()
{
 __asm
 {
     jmp p[525*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal297()
{
 __asm
 {
     jmp p[526*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal296()
{
 __asm
 {
     jmp p[527*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal265()
{
 __asm
 {
     jmp p[528*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal270()
{
 __asm
 {
     jmp p[529*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal271()
{
 __asm
 {
     jmp p[530*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal251()
{
 __asm
 {
     jmp p[531*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal258()
{
 __asm
 {
     jmp p[532*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal259()
{
 __asm
 {
     jmp p[533*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal261()
{
 __asm
 {
     jmp p[534*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal289()
{
 __asm
 {
     jmp p[535*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal288()
{
 __asm
 {
     jmp p[536*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal300()
{
 __asm
 {
     jmp p[537*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal268()
{
 __asm
 {
     jmp p[538*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal253()
{
 __asm
 {
     jmp p[539*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal267()
{
 __asm
 {
     jmp p[540*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal252()
{
 __asm
 {
     jmp p[541*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal256()
{
 __asm
 {
     jmp p[542*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal262()
{
 __asm
 {
     jmp p[543*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal283()
{
 __asm
 {
     jmp p[544*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal290()
{
 __asm
 {
     jmp p[545*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal257()
{
 __asm
 {
     jmp p[546*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal282()
{
 __asm
 {
     jmp p[547*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal291()
{
 __asm
 {
     jmp p[548*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal292()
{
 __asm
 {
     jmp p[549*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal269()
{
 __asm
 {
     jmp p[550*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal287()
{
 __asm
 {
     jmp p[551*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal255()
{
 __asm
 {
     jmp p[552*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal279()
{
 __asm
 {
     jmp p[553*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal281()
{
 __asm
 {
     jmp p[554*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal254()
{
 __asm
 {
     jmp p[555*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal266()
{
 __asm
 {
     jmp p[556*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal293()
{
 __asm
 {
     jmp p[557*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::EnableHash()
{
 __asm
 {
     jmp p[558*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::Unload()
{
 __asm
 {
     jmp p[559*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::GetActualFileName()
{
 __asm
 {
     jmp p[560*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::GetFileSize()
{
 __asm
 {
     jmp p[561*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::GetBasePath()
{
 __asm
 {
     jmp p[562*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::SetBasePath()
{
 __asm
 {
     jmp p[563*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::SetFilePointer()
{
 __asm
 {
     jmp p[564*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::ResetOverlapped()
{
 __asm
 {
     jmp p[565*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::WaitOverlapped()
{
 __asm
 {
     jmp p[566*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::PollOverlapped()
{
 __asm
 {
     jmp p[567*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::Close()
{
 __asm
 {
     jmp p[568*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::CreateOverlapped()
{
 __asm
 {
     jmp p[569*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::DestroyOverlapped()
{
 __asm
 {
     jmp p[570*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::Read()
{
 __asm
 {
     jmp p[571*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::Load()
{
 __asm
 {
     jmp p[572*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::FileExists()
{
 __asm
 {
     jmp p[573*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::Open()
{
 __asm
 {
     jmp p[574*4];
 }
}

extern "C" __declspec(naked) void Proxy_SFile::LoadFile()
{
 __asm
 {
     jmp p[575*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal381()
{
 __asm
 {
     jmp p[576*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal393()
{
 __asm
 {
     jmp p[577*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal388()
{
 __asm
 {
     jmp p[578*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal389()
{
 __asm
 {
     jmp p[579*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal392()
{
 __asm
 {
     jmp p[580*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal385()
{
 __asm
 {
     jmp p[581*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal390()
{
 __asm
 {
     jmp p[582*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal391()
{
 __asm
 {
     jmp p[583*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal382()
{
 __asm
 {
     jmp p[584*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal386()
{
 __asm
 {
     jmp p[585*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal387()
{
 __asm
 {
     jmp p[586*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal383()
{
 __asm
 {
     jmp p[587*4];
 }
}

extern "C" __declspec(naked) void Proxy_SInterlockedIncrement()
{
 __asm
 {
     jmp p[588*4];
 }
}

extern "C" __declspec(naked) void Proxy_SInterlockedDecrement()
{
 __asm
 {
     jmp p[589*4];
 }
}

extern "C" __declspec(naked) void Proxy_SInterlockedExchange()
{
 __asm
 {
     jmp p[590*4];
 }
}

extern "C" __declspec(naked) void Proxy_SInterlockedRead()
{
 __asm
 {
     jmp p[591*4];
 }
}

extern "C" __declspec(naked) void Proxy_SInterlockedExchange()
{
 __asm
 {
     jmp p[592*4];
 }
}

extern "C" __declspec(naked) void Proxy_SInterlockedCompareExchange()
{
 __asm
 {
     jmp p[593*4];
 }
}

extern "C" __declspec(naked) void Proxy_SInterlockedCompareExchangePointer()
{
 __asm
 {
     jmp p[594*4];
 }
}

extern "C" __declspec(naked) void Proxy_SCritSect::SCritSect()
{
 __asm
 {
     jmp p[595*4];
 }
}

extern "C" __declspec(naked) void Proxy_SCritSect::~SCritSect()
{
 __asm
 {
     jmp p[596*4];
 }
}

extern "C" __declspec(naked) void Proxy_SCritSect::Enter()
{
 __asm
 {
     jmp p[597*4];
 }
}

extern "C" __declspec(naked) void Proxy_SCritSect::Leave()
{
 __asm
 {
     jmp p[598*4];
 }
}

extern "C" __declspec(naked) void Proxy_SSyncObject::SSyncObject()
{
 __asm
 {
     jmp p[599*4];
 }
}

extern "C" __declspec(naked) void Proxy_SSyncObject::Wait()
{
 __asm
 {
     jmp p[600*4];
 }
}

extern "C" __declspec(naked) void Proxy_WaitMultiplePtr()
{
 __asm
 {
     jmp p[601*4];
 }
}

extern "C" __declspec(naked) void Proxy_SEvent::Set()
{
 __asm
 {
     jmp p[602*4];
 }
}

extern "C" __declspec(naked) void Proxy_SEvent::Reset()
{
 __asm
 {
     jmp p[603*4];
 }
}

extern "C" __declspec(naked) void Proxy_SThread::Create()
{
 __asm
 {
     jmp p[604*4];
 }
}

extern "C" __declspec(naked) void Proxy_CSRWLock::CSRWLock()
{
 __asm
 {
     jmp p[605*4];
 }
}

extern "C" __declspec(naked) void Proxy_CSRWLock::Leave()
{
 __asm
 {
     jmp p[606*4];
 }
}

extern "C" __declspec(naked) void Proxy_SSyncObject::~SSyncObject()
{
 __asm
 {
     jmp p[607*4];
 }
}

extern "C" __declspec(naked) void Proxy_SEvent::SEvent()
{
 __asm
 {
     jmp p[608*4];
 }
}

extern "C" __declspec(naked) void Proxy_CDebugSCritSect::Enter()
{
 __asm
 {
     jmp p[609*4];
 }
}

extern "C" __declspec(naked) void Proxy_CDebugSCritSect::Leave()
{
 __asm
 {
     jmp p[610*4];
 }
}

extern "C" __declspec(naked) void Proxy_CDebugSRWLock::Leave()
{
 __asm
 {
     jmp p[611*4];
 }
}

extern "C" __declspec(naked) void Proxy_CDebugSCritSect::CDebugSCritSect()
{
 __asm
 {
     jmp p[612*4];
 }
}

extern "C" __declspec(naked) void Proxy_CDebugSCritSect::~CDebugSCritSect()
{
 __asm
 {
     jmp p[613*4];
 }
}

extern "C" __declspec(naked) void Proxy_CSRWLock::~CSRWLock()
{
 __asm
 {
     jmp p[614*4];
 }
}

extern "C" __declspec(naked) void Proxy_CDebugSRWLock::CDebugSRWLock()
{
 __asm
 {
     jmp p[615*4];
 }
}

extern "C" __declspec(naked) void Proxy_CDebugSRWLock::~CDebugSRWLock()
{
 __asm
 {
     jmp p[616*4];
 }
}

extern "C" __declspec(naked) void Proxy_CSRWLock::Enter()
{
 __asm
 {
     jmp p[617*4];
 }
}

extern "C" __declspec(naked) void Proxy_CDebugSRWLock::Enter()
{
 __asm
 {
     jmp p[618*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal541()
{
 __asm
 {
     jmp p[619*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal542()
{
 __asm
 {
     jmp p[620*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal544()
{
 __asm
 {
     jmp p[621*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal545()
{
 __asm
 {
     jmp p[622*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal546()
{
 __asm
 {
     jmp p[623*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal586()
{
 __asm
 {
     jmp p[624*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal587()
{
 __asm
 {
     jmp p[625*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal547()
{
 __asm
 {
     jmp p[626*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal549()
{
 __asm
 {
     jmp p[627*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal585()
{
 __asm
 {
     jmp p[628*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal550()
{
 __asm
 {
     jmp p[629*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal543()
{
 __asm
 {
     jmp p[630*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal553()
{
 __asm
 {
     jmp p[631*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal548()
{
 __asm
 {
     jmp p[632*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal481()
{
 __asm
 {
     jmp p[633*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal491()
{
 __asm
 {
     jmp p[634*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal482()
{
 __asm
 {
     jmp p[635*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal403()
{
 __asm
 {
     jmp p[636*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal406()
{
 __asm
 {
     jmp p[637*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal483()
{
 __asm
 {
     jmp p[638*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal484()
{
 __asm
 {
     jmp p[639*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal404()
{
 __asm
 {
     jmp p[640*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal486()
{
 __asm
 {
     jmp p[641*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal488()
{
 __asm
 {
     jmp p[642*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal490()
{
 __asm
 {
     jmp p[643*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal496()
{
 __asm
 {
     jmp p[644*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal497()
{
 __asm
 {
     jmp p[645*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal487()
{
 __asm
 {
     jmp p[646*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal401()
{
 __asm
 {
     jmp p[647*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal485()
{
 __asm
 {
     jmp p[648*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal489()
{
 __asm
 {
     jmp p[649*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal405()
{
 __asm
 {
     jmp p[650*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal511()
{
 __asm
 {
     jmp p[651*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal413()
{
 __asm
 {
     jmp p[652*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal518()
{
 __asm
 {
     jmp p[653*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal583()
{
 __asm
 {
     jmp p[654*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal418()
{
 __asm
 {
     jmp p[655*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal419()
{
 __asm
 {
     jmp p[656*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal517()
{
 __asm
 {
     jmp p[657*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal582()
{
 __asm
 {
     jmp p[658*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal412()
{
 __asm
 {
     jmp p[659*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal414()
{
 __asm
 {
     jmp p[660*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal420()
{
 __asm
 {
     jmp p[661*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal415()
{
 __asm
 {
     jmp p[662*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal416()
{
 __asm
 {
     jmp p[663*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal417()
{
 __asm
 {
     jmp p[664*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal512()
{
 __asm
 {
     jmp p[665*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal519()
{
 __asm
 {
     jmp p[666*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal513()
{
 __asm
 {
     jmp p[667*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal514()
{
 __asm
 {
     jmp p[668*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal515()
{
 __asm
 {
     jmp p[669*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal516()
{
 __asm
 {
     jmp p[670*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal123()
{
 __asm
 {
     jmp p[671*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal129()
{
 __asm
 {
     jmp p[672*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal131()
{
 __asm
 {
     jmp p[673*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal140()
{
 __asm
 {
     jmp p[674*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal103()
{
 __asm
 {
     jmp p[675*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal104()
{
 __asm
 {
     jmp p[676*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal133()
{
 __asm
 {
     jmp p[677*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal107()
{
 __asm
 {
     jmp p[678*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal111()
{
 __asm
 {
     jmp p[679*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal114()
{
 __asm
 {
     jmp p[680*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal116()
{
 __asm
 {
     jmp p[681*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal120()
{
 __asm
 {
     jmp p[682*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal125()
{
 __asm
 {
     jmp p[683*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal108()
{
 __asm
 {
     jmp p[684*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal109()
{
 __asm
 {
     jmp p[685*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal112()
{
 __asm
 {
     jmp p[686*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal113()
{
 __asm
 {
     jmp p[687*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal124()
{
 __asm
 {
     jmp p[688*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal139()
{
 __asm
 {
     jmp p[689*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal105()
{
 __asm
 {
     jmp p[690*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal106()
{
 __asm
 {
     jmp p[691*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal115()
{
 __asm
 {
     jmp p[692*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal135()
{
 __asm
 {
     jmp p[693*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal127()
{
 __asm
 {
     jmp p[694*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal134()
{
 __asm
 {
     jmp p[695*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal128()
{
 __asm
 {
     jmp p[696*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal130()
{
 __asm
 {
     jmp p[697*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal137()
{
 __asm
 {
     jmp p[698*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal110()
{
 __asm
 {
     jmp p[699*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal136()
{
 __asm
 {
     jmp p[700*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal121()
{
 __asm
 {
     jmp p[701*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal122()
{
 __asm
 {
     jmp p[702*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal117()
{
 __asm
 {
     jmp p[703*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal119()
{
 __asm
 {
     jmp p[704*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal138()
{
 __asm
 {
     jmp p[705*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal102()
{
 __asm
 {
     jmp p[706*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal118()
{
 __asm
 {
     jmp p[707*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal126()
{
 __asm
 {
     jmp p[708*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal101()
{
 __asm
 {
     jmp p[709*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal303()
{
 __asm
 {
     jmp p[710*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal304()
{
 __asm
 {
     jmp p[711*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal427()
{
 __asm
 {
     jmp p[712*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal428()
{
 __asm
 {
     jmp p[713*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal584()
{
 __asm
 {
     jmp p[714*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal421()
{
 __asm
 {
     jmp p[715*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal422()
{
 __asm
 {
     jmp p[716*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal423()
{
 __asm
 {
     jmp p[717*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal424()
{
 __asm
 {
     jmp p[718*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal425()
{
 __asm
 {
     jmp p[719*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal426()
{
 __asm
 {
     jmp p[720*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal429()
{
 __asm
 {
     jmp p[721*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal430()
{
 __asm
 {
     jmp p[722*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal521()
{
 __asm
 {
     jmp p[723*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal534()
{
 __asm
 {
     jmp p[724*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal523()
{
 __asm
 {
     jmp p[725*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal537()
{
 __asm
 {
     jmp p[726*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal530()
{
 __asm
 {
     jmp p[727*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal535()
{
 __asm
 {
     jmp p[728*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal528()
{
 __asm
 {
     jmp p[729*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal536()
{
 __asm
 {
     jmp p[730*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal529()
{
 __asm
 {
     jmp p[731*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal538()
{
 __asm
 {
     jmp p[732*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal531()
{
 __asm
 {
     jmp p[733*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal539()
{
 __asm
 {
     jmp p[734*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal532()
{
 __asm
 {
     jmp p[735*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal540()
{
 __asm
 {
     jmp p[736*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal533()
{
 __asm
 {
     jmp p[737*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal525()
{
 __asm
 {
     jmp p[738*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal524()
{
 __asm
 {
     jmp p[739*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal527()
{
 __asm
 {
     jmp p[740*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal653()
{
 __asm
 {
     jmp p[741*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal650()
{
 __asm
 {
     jmp p[742*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal649()
{
 __asm
 {
     jmp p[743*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal652()
{
 __asm
 {
     jmp p[744*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal651()
{
 __asm
 {
     jmp p[745*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal648()
{
 __asm
 {
     jmp p[746*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal569()
{
 __asm
 {
     jmp p[747*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal571()
{
 __asm
 {
     jmp p[748*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal572()
{
 __asm
 {
     jmp p[749*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal570()
{
 __asm
 {
     jmp p[750*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal508()
{
 __asm
 {
     jmp p[751*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal509()
{
 __asm
 {
     jmp p[752*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal501()
{
 __asm
 {
     jmp p[753*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal506()
{
 __asm
 {
     jmp p[754*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal598()
{
 __asm
 {
     jmp p[755*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal503()
{
 __asm
 {
     jmp p[756*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal578()
{
 __asm
 {
     jmp p[757*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal581()
{
 __asm
 {
     jmp p[758*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal575()
{
 __asm
 {
     jmp p[759*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal576()
{
 __asm
 {
     jmp p[760*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal504()
{
 __asm
 {
     jmp p[761*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal502()
{
 __asm
 {
     jmp p[762*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal580()
{
 __asm
 {
     jmp p[763*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal590()
{
 __asm
 {
     jmp p[764*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal510()
{
 __asm
 {
     jmp p[765*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal579()
{
 __asm
 {
     jmp p[766*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal588()
{
 __asm
 {
     jmp p[767*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal596()
{
 __asm
 {
     jmp p[768*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal597()
{
 __asm
 {
     jmp p[769*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal589()
{
 __asm
 {
     jmp p[770*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal592()
{
 __asm
 {
     jmp p[771*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal591()
{
 __asm
 {
     jmp p[772*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal507()
{
 __asm
 {
     jmp p[773*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal573()
{
 __asm
 {
     jmp p[774*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal574()
{
 __asm
 {
     jmp p[775*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal577()
{
 __asm
 {
     jmp p[776*4];
 }
}

extern "C" __declspec(naked) void Proxy_SGetCurrentThreadId()
{
 __asm
 {
     jmp p[777*4];
 }
}

extern "C" __declspec(naked) void Proxy_SGetCurrentThreadPriority()
{
 __asm
 {
     jmp p[778*4];
 }
}

extern "C" __declspec(naked) void Proxy_SSetCurrentThreadPriority()
{
 __asm
 {
     jmp p[779*4];
 }
}

extern "C" __declspec(naked) void Proxy_SCreateThread()
{
 __asm
 {
     jmp p[780*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal301()
{
 __asm
 {
     jmp p[781*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal302()
{
 __asm
 {
     jmp p[782*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal399()
{
 __asm
 {
     jmp p[783*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal431()
{
 __asm
 {
     jmp p[784*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal432()
{
 __asm
 {
     jmp p[785*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal442()
{
 __asm
 {
     jmp p[786*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal440()
{
 __asm
 {
     jmp p[787*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal441()
{
 __asm
 {
     jmp p[788*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal445()
{
 __asm
 {
     jmp p[789*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal433()
{
 __asm
 {
     jmp p[790*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal446()
{
 __asm
 {
     jmp p[791*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal444()
{
 __asm
 {
     jmp p[792*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal436()
{
 __asm
 {
     jmp p[793*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal438()
{
 __asm
 {
     jmp p[794*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal437()
{
 __asm
 {
     jmp p[795*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal443()
{
 __asm
 {
     jmp p[796*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal447()
{
 __asm
 {
     jmp p[797*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal439()
{
 __asm
 {
     jmp p[798*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal434()
{
 __asm
 {
     jmp p[799*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal901()
{
 __asm
 {
     jmp p[800*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal902()
{
 __asm
 {
     jmp p[801*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal903()
{
 __asm
 {
     jmp p[802*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal904()
{
 __asm
 {
     jmp p[803*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal905()
{
 __asm
 {
     jmp p[804*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal906()
{
 __asm
 {
     jmp p[805*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal907()
{
 __asm
 {
     jmp p[806*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal908()
{
 __asm
 {
     jmp p[807*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal909()
{
 __asm
 {
     jmp p[808*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal910()
{
 __asm
 {
     jmp p[809*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal911()
{
 __asm
 {
     jmp p[810*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal912()
{
 __asm
 {
     jmp p[811*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal913()
{
 __asm
 {
     jmp p[812*4];
 }
}

extern "C" __declspec(naked) void Proxy_Ordinal914()
{
 __asm
 {
     jmp p[813*4];
 }
}


