#include "config.h"
#include <stdio.h>
#include <string.h>
#include <epan/packet.h>

#define FOO_PORT 52118

/* constants for interface types */
#define ZC_VOBC												1
#define ZC_ZC												2
#define VOBC_VOBC											7
#define ATS_VOBC											1001
#define ATS_ZC												1002
#define VOBC_TOD											1003
/* constants for telegram types */
#define TTYPE_NOTUSED										0
#define TTYPE_RFC											1
#define TTYPE_HANDSHAKE										2
#define TTYPE_HANDSHAKECONF									3
#define TTYPE_POLL											4
#define TTYPE_RESPONSE										5
#define TTYPE_SWITCHOVER									6
#define TTYPE_SWITCHOVERCONF								7
#define TTYPE_SYNCHREQUEST									8
#define TTYPE_SYNCHCONF										9
#define TTYPE_SELFIDBROAD									10
/* constants for Receiver Class */
#define RCLASS_VOBC											1
#define RCLASS_ZC											2
#define RCLASS_ATS											5
#define RCLASS_TOD											6
#define RCLASS_DATALOGGER									7
#define RCLASS_TDMS											8
/* constants for Transmitter Class */
#define TCLASS_VOBC											1
#define TCLASS_ZC											2
#define TCLASS_ATS											5
#define TCLASS_TOD											6
#define TCLASS_DATALOGGER									7
#define TCLASS_TDMS											8
/* constants for VOBC Active Status */
#define VOBC_PASSIVE										0
#define VOBC_ACTIVE											1
#define VOBC_PASSIVEAVAILABLE								2
/* constants for travel direction */
#define TRVDIR_GD0											0
#define TRVDIR_GD1											1
#define TRVDIR_UNK											2
/* constants for Train integrity */
#define TRAININTEGRITY_LOST									0
#define TRAININTEGRITY_ESTABLISHED							1
#define TRAININTEGRITY_UNKNOWN								2
/* constants for Reported Run Type */
#define RUNTYPE_ENERGYCONSERVATION							1
#define RUNTYPE_NORMAL										2
#define RUNTYPE_FIRSTINTERMEDIARY							3
#define RUNTYPE_SECONDINTERMEDIARY							4
#define RUNTYPE_ACCELERATED									5
/* constants for Station Skip */
#define STATIONSKIP_NONE									0
#define STATIONSKIP_ACTIVE									1
/* constants for Train Alignment status */
#define TRAINALIGNMENT_NONE									0
#define TRAINALIGNMENT_ALIGNED								1
/* constants for Arrival Type*/
#define ARRIVALTYPE_NOTARRIVED								0
#define ARRIVALTYPE_PLATFORM								1
#define ARRIVALTYPE_SIGNAL									2
/* constants for Reported Reduce Rate */
#define REPORTEDREDUCERATE_NONE								0
#define REPORTEDREDUCERATE_TYPE1							1
#define REPORTEDREDUCERATE_TYPE2							2
/* constants for Stop Now */
#define STOPNOWSTATUS_NOTACTIVE								0
#define STOPNOWSTATUS_ACTIVE								1
/* constants for Storage Mode Status */
#define STORAGEMODESTATUS_NONE								0
#define STORAGEMODESTATUS_ACTIVE							1
/* constants for Train Propulsion Control Command */
#define TRAINPROPULSION_NONE								0
#define TRAINPROPULSION_MOTORING							1
#define TRAINPROPULSION_COASTING							2
#define TRAINPROPULSION_BRAKING								3
/* constants for Train Overshoot over crawlback distance */
#define TRAINOVERSHOOT_NONE									0
#define TRAINOVERSHOOT_OVERSHOOTOVERCRAWLBACK				1

/* String constants for display */
#define VOBC2ATS											"VOBC2ATS ICD"
#define ATS2VOBC											"ATS2VOBC ICD"
#define VOBC2VOBC											"VOBC2VOBC ICD"
#define VOBC2ZC												"VOBC2ZC ICD"
#define ZC2VOBC												"ZC2VOBC ICD"
#define UNKNOWN												"UNKNOWN"
/* String constants for column info display*/
#define VOBC2ATS_COLINFODISPLAY								"[VOBC -> ATS]"
#define ATS2VOBC_COLINFODISPLAY								"[ATS -> VOBC]"
#define VOBC2VOBC_COLINFODISPLAY							"[VOBC -> VOBC]"
#define VOBC2ZC_COLINFODISPLAY								"[VOBC -> ZC]"
#define ZC2VOBC_COLINFODISPLAY								"[ZC -> VOBC]"
/* String constants fo eb status */
#define EBSTATUS_NOTAPPLIED									"EB not applied (0)"
#define EBSTATUS_APPLIED									"EB applied (1)"
#define EBSTATUS_UNKNOWN									"Unknown"
#define EBSTATUS_REMOTEEBRESETAVAILABLE						"EB applied, Remote EB reset available (2)"
#define EBSTATUS_REMOTEEBRESETNOTAVAILABLE					"Remote EB reset not available (3)"

/* String constants for train door status*/
#define TRAINDOORS_NOTCLOSEDANDLOCKED						"Left/Right Train doors not closed and locked (0)"
#define TRAINDOORS_CLOSEDANDLOCKED							"Left/Right Train doors closed and locked (3)"

/* String constants for train door open mode*/
#define TRAINDOORSMODE_MANUAL								"Manual (0)"
#define TRAINDOORSMODE_AUTOMATIC							"Automatic (1)"

/* String constants for operating mode */
#define OPERATINGMODE_ATPM									"ATP Manual (2)"
#define OPERATINGMODE_OFF									"Off (6)"
#define OPERATINGMODE_RMF									"Restricted Manual Forward (7)"
#define OPERATINGMODE_RMR									"Restricted Manual Reverse (8)"
#define OPERATINGMODE_AM									"Automatic Mode (10)"
#define OPERATINGMODE_DTO									"Driverless Train Operation (11)"
#define OPERATINGMODE_PASSIVEINVALID						"Passive/Invalid (63)"
#define OPERATINGMODE_STANDBY								"Standby (13)"
#define OPERATINGMODE_SHADOW								"Shadow (14)"

/* String constants for  mode disallowed */
#define MODEDISALLOW_NONE									"No modes Disallowed (0)"
#define MODEDISALLOW_ATPM									"ATPM Disallowed (1)"
#define MODEDISALLOW_AM										"AM Disallowed (2)"
#define MODEDISALLOW_AMATPM									"ATPM/AM Disallowed (3)"

/* Platform hold status */
#define PLATFROMHOLD_NONE									"No Platform hold is in effect (0)"
#define PLATFROMHOLD_ACTIVE									"Platform hold is in effect (6)"

/* Platform hold flag*/
#define PLATFORMHOLDFLAG_NOHOLD								"No Hold (0)"
#define PLATFORMHOLDFLAG_VOBCIMPOSED						"VOBC self-imposed Hold (1)"


#define MSG_HEADER_LENGTH_VITAL_TELEGRAM					41
#define MSG_HEADER_LENGTH_NONVITAL_TELEGRAM					33

static int proto_thalesauric								= -1;
static int hf_thalesauric_iType								= -1;
static int hf_thalesauric_iVersion							= -1;
static int hf_thalesauric_icddata							= -1;
static int hf_thalesauric_telegramType						= -1;
static int hf_thalesauric_receiverClass						= -1;
static int hf_thalesauric_receiverId						= -1;
static int hf_thalesauric_transmitterClass					= -1;
static int hf_thalesauric_transmitterId						= -1;
static int hf_thalesauric_transmityear						= -1;
static int hf_thalesauric_transmitmonth						= -1;
static int hf_thalesauric_transmitday					    = -1;
static int hf_thalesauric_transmithour						= -1;
static int hf_thalesauric_transmitminute					= -1;
static int hf_thalesauric_transmitsecond					= -1;
static int hf_thalesauric_transmitmillisecond				= -1;
static int hf_thalesauric_rsn								= -1;
static int hf_thalesauric_tsn								= -1;
static int hf_thalesauric_rcclcc							= -1;
static int hf_thalesauric_dcn								= -1;
static int hf_thalesauric_datalength						= -1;
static int hf_thalesauric_data								= -1;
static int hf_thalesauric_firstcrc							= -1;
static int hf_vobc2atsicd_vobcswversion						= -1;
static int hf_vobc2atsicd_vobcdbversion						= -1;
static int hf_vobc2atsicd_trainid							= -1;
static int hf_vobc2atsicd_vobcid							= -1;
static int hf_vobc2atsicd_vobcactivestatus					= -1;
static int hf_vobc2atsicd_numberofvehicles					= -1;
static int hf_vobc2atsicd_vehiclelist						= -1;
static int hf_vobc2atsicd_traveldirection					= -1;
static int hf_vobc2atsicd_trainrearsegment					= -1;
static int hf_vobc2atsicd_trainrearoffset					= -1;
static int hf_vobc2atsicd_trainfrontsegment					= -1;
static int hf_vobc2atsicd_trainfrontoffset					= -1;
static int hf_vobc2atsicd_numberofsegmentsoccupied			= -1;
static int hf_vobc2atsicd_listofsegments					= -1;
static int hf_vobc2atsicd_velocity							= -1;
static int hf_vobc2atsicd_ebstatus							= -1;
static int hf_vobc2atsicd_traindoorstatus					= -1;
static int hf_vobc2atsicd_traindooropenmode					= -1;
static int hf_vobc2atsicd_traindoorclosemode				= -1;
static int hf_vobc2atsicd_operatingmode						= -1;
static int hf_vobc2atsicd_modedisallowed					= -1;
static int hf_vobc2atsicd_trainintegrity					= -1;
static int hf_vobc2atsicd_reportedruntype					= -1;
static int hf_vobc2atsicd_platformholdstatus				= -1;
static int hf_vobc2atsicd_platformholdflag					= -1;
static int hf_vobc2atsicd_stationskipstatus					= -1;
static int hf_vobc2atsicd_trainalignmentstatus				= -1;
static int hf_vobc2atsicd_arrivaltype						= -1;
static int hf_vobc2atsicd_arrivalid							= -1;
static int hf_vobc2atsicd_reportedreducerate				= -1;
static int hf_vobc2atsicd_stopnowstatus						= -1;
static int hf_vobc2atsicd_storagemodestatus					= -1;
static int hf_vobc2atsicd_trainovershootundershootstatus	= -1;
static int hf_vobc2atsicd_traincrawlingback					= -1;
static int hf_vobc2atsicd_trainjoggingforwardbackward		= -1;
static int hf_vobc2atsicd_couplingprogress					= -1;
static int hf_vobc2atsicd_trainpropulsioncontrolcommand		= -1;
static int hf_vobc2atsicd_trainovershootovercrawlbackdistance = -1;


static int ett_thalesauric									= -1;
static int ett_thalesauric_header							= -1;
static int ett_thalesauric_data								= -1;

static char	colinfodisplay[100];

/*Interface Type */
static const value_string ta_iType[] = {
	{ ZC_VOBC, "ZC <--> VOBC" },
	{ ZC_ZC, "ZC <--> ZC" },
	{ VOBC_VOBC, "VOBC <--> VOBC" },
	{ ATS_VOBC, "ATS <--> VOBC" },
	{ ATS_ZC, "ATS <--> ZC" },
	{ VOBC_TOD, "VOBC <--> TOD" },
	{ 0, NULL }
};

/* Telegram Type */
static const value_string ta_telegramType[] = {
	{ TTYPE_NOTUSED, "Not Used" },
	{ TTYPE_RFC, "Request for Communication" },
	{ TTYPE_HANDSHAKE, "Handshake" },
	{ TTYPE_HANDSHAKECONF, "Handshake Confirmation" },
	{ TTYPE_POLL, "Poll" },
	{ TTYPE_RESPONSE, "Response" },
	{ TTYPE_SWITCHOVER, "Switchover" },
	{ TTYPE_SWITCHOVERCONF, "Switchover Confirmation" },
	{ TTYPE_SYNCHREQUEST, "Synchronization Request" },
	{ 0, NULL }
};

/* Receiver Class */
static const value_string ta_receiverClass[] = {
	{ RCLASS_VOBC, "VOBC" },
	{ RCLASS_ZC, "ZC" },
	{ RCLASS_ATS, "ATS" },
	{ RCLASS_TOD, "TOD" },
	{ RCLASS_DATALOGGER, "Datalogger" },
	{ RCLASS_TDMS, "TDMS" },
	{ 0, NULL }
};


/* Transmitter Class */
static const value_string ta_transmitterClass[] = {
	{ TCLASS_VOBC, "VOBC" },
	{ TCLASS_ZC, "ZC" },
	{ TCLASS_ATS, "ATS" },
	{ TCLASS_TOD, "TOD" },
	{ TCLASS_DATALOGGER, "Datalogger" },
	{ TCLASS_TDMS, "TDMS" },
	{ 0, NULL }
};

/* VOBC Active Status */
static const value_string vobc2ats_vobcactivestatus[] = {
	{ VOBC_PASSIVE, "Passive" },
	{ VOBC_ACTIVE, "Active" },
	{ VOBC_PASSIVEAVAILABLE, "Passive Available" },
	{ 0, NULL }
};

/* Travel Direction  */
static const value_string vobc2ats_traveldirection[] = {
	{ TRVDIR_GD0, "GD0" },
	{ TRVDIR_GD1, "GD1" },
	{ TRVDIR_UNK, "Unknown" },
	{ 0, NULL }
};

/* Train Integrity */
static const value_string vobc2ats_trainintegrity[] = {
	{ TRAININTEGRITY_LOST, "Lost" },
	{ TRAININTEGRITY_ESTABLISHED, "Established" },
	{ TRAININTEGRITY_UNKNOWN, "Unknown" },
	{ 0, NULL }
};

/* Reported Run Type */
static const value_string vobc2ats_reportedruntype[] = {
	{ RUNTYPE_ENERGYCONSERVATION, "Energy Conservation Run" },
	{ RUNTYPE_NORMAL, "Normal Run" },
	{ RUNTYPE_FIRSTINTERMEDIARY, "First Intermediary Run" },
	{ RUNTYPE_SECONDINTERMEDIARY, "Second Intermediary Run" },
	{ RUNTYPE_ACCELERATED, "Accelerated Run" },
	{ 0, NULL }
};

/* Station Skip */
static const value_string vobc2ats_stationskipstatus[] = {
	{ STATIONSKIP_NONE, "None" },
	{ STATIONSKIP_ACTIVE, "Active" },
	{ 0, NULL }
};

/* Train Alignment */
static const value_string vobc2ats_trainalignmentstatus[] = {
	{ TRAINALIGNMENT_NONE, "None" },
	{ TRAINALIGNMENT_ALIGNED, "Aligned" },
	{ 0, NULL }
};

/* Arrival Type */
static const value_string vobc2ats_arrivaltype[] = {
	{ ARRIVALTYPE_NOTARRIVED, "Not Arrived" },
	{ ARRIVALTYPE_PLATFORM, "Platform" },
	{ ARRIVALTYPE_SIGNAL, "Signal" },
	{ 0, NULL }
};

/* Reported Reduce Rate */
static const value_string vobc2ats_reportedreducerate[] = {
	{ REPORTEDREDUCERATE_NONE, "None" },
	{ REPORTEDREDUCERATE_TYPE1, "Type I" },
	{ REPORTEDREDUCERATE_TYPE2, "Type II" },
	{ 0, NULL }
};

/* Stop Now Status */
static const value_string vobc2ats_stopnowstatus[] = {
	{ STOPNOWSTATUS_NOTACTIVE, "None" },
	{ STOPNOWSTATUS_ACTIVE, "Active" },
	{ 0, NULL }
};

/* Storage Mode Status */
static const value_string vobc2ats_storagemodestatus[] = {
	{ STORAGEMODESTATUS_NONE, "None" },
	{ STORAGEMODESTATUS_ACTIVE, "Active" },
	{ 0, NULL }
};

/* Train Overshoot Undershoot Status */
static const value_string vobc2ats_trainovershootundershootstatus[] = {
	{ 0, NULL }
};

/* Train Crawling Back */
static const value_string vobc2ats_traincrawlingback[] = {
	{ 0, NULL }
};

/* Train Jogging Forward Backward */
static const value_string vobc2ats_trainjoggingforwardbackward[] = {
	{ 0, NULL }
};

/* Coupling Progress */
static const value_string vobc2ats_couplingprogress[] = {
	{ 0, NULL }
};

/* Train Propulsion Control  */
static const value_string vobc2ats_trainpropulsioncontrolcommand[] = {
	{ TRAINPROPULSION_NONE, "None" },
	{ TRAINPROPULSION_MOTORING, "Motoring" },
	{ TRAINPROPULSION_COASTING, "Coasting" },
	{ TRAINPROPULSION_BRAKING, "Braking" },
	{ 0, NULL }
};

/* Train Overshoot over crawlback distance  */
static const value_string vobc2ats_trainovershootovercrawlbackdistance[] = {
	{ TRAINOVERSHOOT_NONE, "None" },
	{ TRAINOVERSHOOT_OVERSHOOTOVERCRAWLBACK, "Train overshoot more than crawlback distance" },
	{ 0, NULL }
};

extern "C"  void
proto_register_foo(void)
{

	static hf_register_info hf[] = {
		{ &hf_thalesauric_iType,
		{ "Interface Type", "thalesauric.interfacetype", FT_UINT16, BASE_DEC, VALS(ta_iType), 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_telegramType,
		{ "Telegram Type", "thalesauric.telegramtype", FT_UINT16, BASE_DEC, VALS(ta_telegramType), 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_receiverClass,
		{ "Receiver Class", "thalesauric.receiverclass", FT_UINT16, BASE_DEC, VALS(ta_receiverClass), 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmitterClass,
		{ "Transmitter Class", "thalesauric.transmitterclass", FT_UINT16, BASE_DEC, VALS(ta_transmitterClass), 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_iVersion,
		{ "Interface Version", "thalesauric.interfaceversion", FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_receiverId,
		{ "Receiver Id", "thalesauric.receiverid", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmitterId,
		{ "Transmitter Id", "thalesauric.transmitterid", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmityear,
		{ "Year", "thalesauric.year", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmitmonth,
		{ "Month", "thalesauric.month", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmitday,
		{ "Day", "thalesauric.day", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmithour,
		{ "Hour", "thalesauric.hour", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmitminute,
		{ "Minute", "thalesauric.minute", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmitsecond,
		{ "Second", "thalesauric.second", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_transmitmillisecond,
		{ "Millisecond", "thalesauric.millisecond", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_rcclcc,
		{ "RCC_LCC Data", "thalesauric.rcclcc", FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_dcn,
		{ "Database Compatibility Number", "thalesauric.dcn", FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_rsn,
		{ "RSN", "thalesauric.rsn", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_tsn,
		{ "TSN", "thalesauric.tsn", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_datalength,
		{ "Data Length", "thalesauric.datalength", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_data,
		{ "Data", "thalesauric.data", FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_firstcrc,
		{ "firstcrc", "thalesauric.firstcrc", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_vobcswversion,
		{ "vobc_sw_version", "vobc2ats.vobc_sw_version", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_vobcdbversion,
		{ "vobc_db_version", "vobc2ats.vobc_db_version", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainid,
		{ "train_id", "vobc2ats.train_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_vobcid,
		{ "vobc_id", "vobc2ats.vobc_id", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_vobcactivestatus,
		{ "vobc_active_status", "vobc2ats.vobc_active_status", FT_UINT8, BASE_DEC, VALS(vobc2ats_vobcactivestatus), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_numberofvehicles,
		{ "number_of_vehicles", "vobc2ats.number_of_vehicles", FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_vehiclelist,
		{ "vehicle_list" , "vobc2ats.vehicle_list", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_traveldirection,
		{ "travel_direction", "vobc2ats.travel_direction", FT_UINT8, BASE_DEC, VALS(vobc2ats_traveldirection), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainrearsegment,
		{ "train_rear_segment", "vobc2ats.train_rear_segment", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainrearoffset,
		{ "train_rear_offset", "vobc2ats.train_rear_offset", FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainfrontsegment,
		{ "train_front_segment", "vobc2ats.train_front_segment", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainfrontoffset,
		{ "train_front_offset", "vobc2ats.train_front_offset", FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_numberofsegmentsoccupied,
		{ "train_number_of_segments_occupied", "vobc2ats.train_number_of_segments_occupied", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_listofsegments,
		{ "train_occupied_segments", "vobc2ats.train_occupied_segments", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_velocity,
		{ "velocity", "vobc2ats.velocity", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_ebstatus,
		{ "eb_status", "vobc2ats.eb_status", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_traindoorstatus,
		{ "train_door_status", "vobc2ats.train_door_status", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_traindooropenmode,
		{ "train_door_open_mode", "vobc2ats.train_door_open_mode", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_traindoorclosemode,
		{ "train_door_close_mode", "vobc2ats.train_door_close_mode", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_operatingmode,
		{ "operating_mode", "vobc2ats.operating_mode", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_modedisallowed,
		{ "mode_disallowed", "vobc2ats.mode_disallowed", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainintegrity,
		{ "train_integrity", "vobc2ats.train_integrity", FT_UINT8, BASE_DEC, VALS(vobc2ats_trainintegrity), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_reportedruntype,
		{ "reported_run_type", "vobc2ats.reported_run_type", FT_UINT8, BASE_DEC, VALS(vobc2ats_reportedruntype), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_platformholdstatus,
		{ "platform_hold_status", "vobc2ats.platform_hold_status", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_platformholdflag,
		{ "platform_hold_flag", "vobc2ats.platform_hold_flag", FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_stationskipstatus,
		{ "station_skip_status", "vobc2ats.station_skip_status", FT_UINT8, BASE_DEC, VALS(vobc2ats_stationskipstatus), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainalignmentstatus,
		{ "train_alignment_status", "vobc2ats.train_alignment_status", FT_UINT8, BASE_DEC, VALS(vobc2ats_trainalignmentstatus), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_arrivaltype,
		{ "arrival_type", "vobc2ats.arrival_type", FT_UINT8, BASE_DEC, VALS(vobc2ats_arrivaltype), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_arrivalid,
		{ "arrival_id", "vobc2ats.arrival_id", FT_UINT16, BASE_DEC, NULL, 0x0,	NULL, HFILL } },
		{ &hf_vobc2atsicd_reportedreducerate,
		{ "reported_reduce_rate", "vobc2ats.reported_reduce_rate", FT_UINT8, BASE_DEC, VALS(vobc2ats_reportedreducerate), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_stopnowstatus,
		{ "stop_now_status", "vobc2ats.stop_now_status", FT_UINT8, BASE_DEC, VALS(vobc2ats_stopnowstatus), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_storagemodestatus,
		{ "storage_mode_status", "vobc2ats.storage_mode_status", FT_UINT8, BASE_DEC, VALS(vobc2ats_storagemodestatus), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainovershootundershootstatus,
		{ "train_overshoot_undershoot_status", "vobc2ats.train_overshoot_undershoot_status", FT_UINT8, BASE_DEC, VALS(vobc2ats_trainovershootundershootstatus), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_traincrawlingback,
		{ "train_crawling_back", "vobc2ats.train_crawling_back", FT_UINT8, BASE_DEC, VALS(vobc2ats_traincrawlingback), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainjoggingforwardbackward,
		{ "train_jogging_forward_backward", "vobc2ats.train_jogging_forward_backward", FT_UINT8, BASE_DEC, VALS(vobc2ats_trainjoggingforwardbackward), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_couplingprogress,
		{ "coupling_progress", "vobc2ats.coupling_progress", FT_UINT8, BASE_DEC, VALS(vobc2ats_couplingprogress), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainpropulsioncontrolcommand,
		{ "train_propulsion_control_command", "vobc2ats.train_propulsion_control_command", FT_UINT8, BASE_DEC, VALS(vobc2ats_trainpropulsioncontrolcommand), 0x0,
		NULL, HFILL } },
		{ &hf_vobc2atsicd_trainovershootovercrawlbackdistance,
		{ "train_overshoot_over_crawlback_distance", "vobc2ats.train_overshoot_over_crawlback_distance", FT_UINT8, BASE_DEC, VALS(vobc2ats_trainovershootovercrawlbackdistance), 0x0,
		NULL, HFILL } },
		{ &hf_thalesauric_icddata,
		{ "Data", "thalesauric.icd", FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL } }
	};
	static gint *ett[] = {
		&ett_thalesauric,
		&ett_thalesauric_header,
		&ett_thalesauric_data
	};

	proto_thalesauric = proto_register_protocol(
        "FOO Protocol", /* name       */
        "FOO",      /* short name */
        "foo"       /* abbrev     */
        );

	proto_register_field_array(proto_thalesauric, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

int process_vobc2ats_vobcswversion(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	char version_buffer[15];
	unsigned short patch_version = tvb_get_letohs(tvb, offset);
	unsigned short minor_version = tvb_get_guint8(tvb, offset + 2);
	unsigned short major_version = tvb_get_guint8(tvb, offset + 3);

	sprintf(version_buffer, "%d.%02d.%02d", major_version, minor_version, patch_version);
	proto_tree_add_string(tree, hf_vobc2atsicd_vobcswversion, tvb, offset, 4, version_buffer);
	return 4;
}

int process_vobc2ats_vobcdbversion(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	char version_buffer[15];
	unsigned short patch_version = tvb_get_letohs(tvb, offset);
	unsigned short minor_version = tvb_get_guint8(tvb, offset + 2);
	unsigned short major_version = tvb_get_guint8(tvb, offset + 3);

	sprintf(version_buffer, "%d.%02d.%02d", major_version, minor_version, patch_version);
	proto_tree_add_string(tree, hf_vobc2atsicd_vobcdbversion, tvb, offset, 4, version_buffer);
	return 4;
}

int process_vobc2ats_trainid(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	return 2;
}

int process_vobc2ats_vobcid(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_vobcid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	return 2;
}

int process_vobc2ats_vobcactivestatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_vobcactivestatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_numberofvehicles_vehiclelist(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	int numreadbytes = 0;
	unsigned char numvehicles = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(tree, hf_vobc2atsicd_numberofvehicles, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	numreadbytes++;
	for (int i = 0; i < numvehicles; i++)
	{
		char vehiclestr[20];
		int vehicleid = tvb_get_letohs(tvb, offset + numreadbytes);
		sprintf(vehiclestr, "vehicle[%d]:%d", i, vehicleid);
		proto_tree_add_string_format(tree, hf_vobc2atsicd_vehiclelist, tvb, offset + numreadbytes, 2, vehiclestr, "%s", vehiclestr);
		numreadbytes += 2;
	}

	return numreadbytes;
}

int process_vobc2ats_traveldirection(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_traveldirection, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_trainrearsegment(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainrearsegment, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	return 2;
}

int process_vobc2ats_trainrearoffset(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainrearoffset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	return 4;
}

int process_vobc2ats_trainfrontsegment(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainfrontsegment, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	return 2;
}

int process_vobc2ats_trainfrontoffset(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainfrontoffset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	return 4;
}

int process_vobc2ats_numberofsegments_numberofsegmentsoccupied(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	int numreadbytes = 0;
	unsigned short numberofsegments = tvb_get_letohs(tvb, offset);

	proto_tree_add_item(tree, hf_vobc2atsicd_numberofsegmentsoccupied, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	numreadbytes+=2;
	for (int i = 0; i < numberofsegments; i++)
	{
		char occupiedsegmentstr[50];
		int segmentid = tvb_get_letohs(tvb, offset + numreadbytes);
		sprintf(occupiedsegmentstr, "train_number_of_segments_occupied[%d]:%d", i, segmentid);
		proto_tree_add_string_format(tree, hf_vobc2atsicd_listofsegments, tvb, offset + numreadbytes, 2, occupiedsegmentstr, "%s", occupiedsegmentstr);
		numreadbytes += 2;
	}

	return numreadbytes;
}

int process_vobc2ats_velocity(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_velocity, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	return 2;
}

int process_vobc2ats_ebstatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	short ebstatus = tvb_get_guint8(tvb, offset);

	switch (ebstatus)
	{
	case 0:
		proto_tree_add_string(tree, hf_vobc2atsicd_ebstatus, tvb, offset, 1, EBSTATUS_NOTAPPLIED);
		break;
	case 1:
		proto_tree_add_string(tree, hf_vobc2atsicd_ebstatus, tvb, offset, 1, EBSTATUS_APPLIED);
		break;
	case 2:
		proto_tree_add_string(tree, hf_vobc2atsicd_ebstatus, tvb, offset, 1, EBSTATUS_UNKNOWN);
		break;
	case 3:
		proto_tree_add_string(tree, hf_vobc2atsicd_ebstatus, tvb, offset, 1, EBSTATUS_REMOTEEBRESETAVAILABLE);
		break;
	default:
		proto_tree_add_string(tree, hf_vobc2atsicd_ebstatus, tvb, offset, 1, EBSTATUS_REMOTEEBRESETNOTAVAILABLE);
	}
	return 1;
}

int process_vobc2ats_traindoorcontrolstatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	guint8 traindoorcontrolstatus		= tvb_get_guint8(tvb, offset);
	guint8 traindoorstatus				= traindoorcontrolstatus & 0xF;
	guint8 traindooropenmode			= (traindoorcontrolstatus & 0x30) >> 4;
	guint8 traindoorclosemode			= (traindoorcontrolstatus & 0xC0) >> 6;


	switch (traindoorstatus)
	{
	case 0:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindoorstatus, tvb, offset, 1, TRAINDOORS_NOTCLOSEDANDLOCKED);
		break;
	case 3:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindoorstatus, tvb, offset, 1, TRAINDOORS_CLOSEDANDLOCKED);
		break;
	default:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindoorstatus, tvb, offset, 1, UNKNOWN);
		break;
	}

	switch(traindooropenmode)
	{
	case 0:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindooropenmode, tvb, offset, 1, TRAINDOORSMODE_MANUAL);
		break;
	case 1:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindooropenmode, tvb, offset, 1, TRAINDOORSMODE_AUTOMATIC);
		break;
	default:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindooropenmode, tvb, offset, 1, UNKNOWN);
		break;
	}

	switch (traindoorclosemode)
	{
	case 0:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindoorclosemode, tvb, offset, 1, TRAINDOORSMODE_MANUAL);
		break;
	case 1:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindoorclosemode, tvb, offset, 1, TRAINDOORSMODE_AUTOMATIC);
		break;
	default:
		proto_tree_add_string(tree, hf_vobc2atsicd_traindoorclosemode, tvb, offset, 1, UNKNOWN);
		break;
	}

	return 1;
}


int process_vobc2ats_trainintegrity(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainintegrity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_operatingmode_modedisallowed(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	guint8 buffer = tvb_get_guint8(tvb, offset);
	guint8 operatingmode = buffer & 0x3F;
	guint8 modedisallowed = (buffer & 0xC0) >> 6;
	


	switch (operatingmode)
	{
	case 2:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_ATPM);
		break;
	case 6:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_OFF);
		break;
	case 7:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_RMF);
		break;
	case 8:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_RMR);
		break;
	case 10:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_AM);
		break;
	case 11:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_DTO);
		break;
	case 13:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_STANDBY);
		break;
	case 14:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_SHADOW);
		break;
	case 63:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, OPERATINGMODE_PASSIVEINVALID);
		break;
	default:
		proto_tree_add_string(tree, hf_vobc2atsicd_operatingmode, tvb, offset, 1, UNKNOWN);
		break;
	}

	switch (modedisallowed)
	{
	case 0:
		proto_tree_add_string(tree, hf_vobc2atsicd_modedisallowed, tvb, offset, 1, MODEDISALLOW_NONE);
		break;
	case 1:
		proto_tree_add_string(tree, hf_vobc2atsicd_modedisallowed, tvb, offset, 1, MODEDISALLOW_ATPM);
		break;
	case 2:
		proto_tree_add_string(tree, hf_vobc2atsicd_modedisallowed, tvb, offset, 1, MODEDISALLOW_AM);
		break;
	case 3:
		proto_tree_add_string(tree, hf_vobc2atsicd_modedisallowed, tvb, offset, 1, MODEDISALLOW_AMATPM);
		break;
	default:
		proto_tree_add_string(tree, hf_vobc2atsicd_modedisallowed, tvb, offset, 1, UNKNOWN);
		break;
	}

	

	return 1;
}

int process_vobc2ats_reportedruntype(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_reportedruntype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_platformholdstatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	guint8 buffer = tvb_get_guint8(tvb, offset);
	guint8 platformholdstatus = buffer & 0x3F;
	guint8 platformholdflag= (buffer & 0xC0) >> 6;



	switch (platformholdstatus)
	{
	case 0:
		proto_tree_add_string(tree, hf_vobc2atsicd_platformholdstatus, tvb, offset, 1, PLATFROMHOLD_NONE);
		break;
	case 6:
		proto_tree_add_string(tree, hf_vobc2atsicd_platformholdstatus, tvb, offset, 1, PLATFROMHOLD_ACTIVE);
		break;
	default:
		proto_tree_add_string(tree, hf_vobc2atsicd_platformholdstatus, tvb, offset, 1, UNKNOWN);
		break;
	}

	switch (platformholdflag)
	{
	case 0:
		proto_tree_add_string(tree, hf_vobc2atsicd_platformholdflag, tvb, offset, 1, PLATFORMHOLDFLAG_NOHOLD);
		break;
	case 1:
		proto_tree_add_string(tree, hf_vobc2atsicd_platformholdflag, tvb, offset, 1, PLATFORMHOLDFLAG_VOBCIMPOSED);
		break;
	default:
		proto_tree_add_string(tree, hf_vobc2atsicd_platformholdflag, tvb, offset, 1, UNKNOWN);
		break;
	}

	return 1;
}

int process_vobc2ats_stationskipstatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_stationskipstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_trainalignmentstatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainalignmentstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_arrivaltype(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_arrivaltype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_arrivalid(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_arrivalid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	return 2;
}

int process_vobc2ats_reportedreducerate(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_reportedreducerate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_stopnowstatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_stopnowstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_storagemodestatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_storagemodestatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_trainovershootundershootstatus(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainovershootundershootstatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_traincrawlingback(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_traincrawlingback, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_trainjoggingforwardbackward(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainjoggingforwardbackward, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_couplingprogress(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_couplingprogress, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_trainpropulsioncontrolcommand(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainpropulsioncontrolcommand, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}

int process_vobc2ats_trainovershootovercrawlbackdistance(proto_tree *tree, tvbuff_t *tvb, unsigned short offset)
{
	proto_tree_add_item(tree, hf_vobc2atsicd_trainovershootovercrawlbackdistance, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return 1;
}


int (*vobc2ats_func[])(proto_tree *tree, tvbuff_t *tvb, unsigned short offset) = 
	{ process_vobc2ats_vobcswversion, 
	  process_vobc2ats_vobcdbversion,
	  process_vobc2ats_trainid,
	  process_vobc2ats_vobcid,
	  process_vobc2ats_vobcactivestatus,
	  process_vobc2ats_numberofvehicles_vehiclelist,
	  process_vobc2ats_traveldirection,
	  process_vobc2ats_trainrearsegment,
	  process_vobc2ats_trainrearoffset,
	  process_vobc2ats_trainfrontsegment,
	  process_vobc2ats_trainfrontoffset,
	  process_vobc2ats_numberofsegments_numberofsegmentsoccupied,
	  process_vobc2ats_velocity,
	  process_vobc2ats_ebstatus,
	  process_vobc2ats_traindoorcontrolstatus,
	  process_vobc2ats_operatingmode_modedisallowed,
	  process_vobc2ats_trainintegrity,
	  process_vobc2ats_reportedruntype,
	  process_vobc2ats_platformholdstatus,
	  process_vobc2ats_stationskipstatus,
	  process_vobc2ats_trainalignmentstatus,
	  process_vobc2ats_arrivaltype,
	  process_vobc2ats_arrivalid,
	  process_vobc2ats_reportedreducerate,
	  process_vobc2ats_stopnowstatus,
	  process_vobc2ats_storagemodestatus,
	  process_vobc2ats_trainovershootundershootstatus,
	  process_vobc2ats_traincrawlingback,
	  process_vobc2ats_trainjoggingforwardbackward,
	  process_vobc2ats_couplingprogress,
	  process_vobc2ats_trainpropulsioncontrolcommand,
	  process_vobc2ats_trainovershootovercrawlbackdistance,
	NULL };

int processVOBC2ATSdata(proto_tree *tree, tvbuff_t *tvb, unsigned short offset, unsigned datalength)
{
	int readindex = 0;
	int readbytes = 0;

	while (vobc2ats_func[readindex] != NULL && readbytes < datalength)
	{
		unsigned short readbytescurrentfunction;

		readbytescurrentfunction = vobc2ats_func[readindex](tree, tvb, offset + readbytes);
		readbytes += readbytescurrentfunction;
		readindex++;
	}
	return readbytes;
}



static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree      *thalesauric_tree = NULL;
	proto_tree      *header_tree = NULL, *body_tree = NULL;
	unsigned short  interfaceType;
	unsigned short  receiverClass;
	unsigned short  transmitterClass;
	int				offset					= 0;
	unsigned char   header_length			= 0;
	unsigned short	dataLength				= 0;
	unsigned short	offset_data				= 0;
	unsigned short  rsn						= 0;
	unsigned short  tsn						= 0;
	
	char			buficddisplay[15];
	char			colicddisplay[15];


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "marc_thalesauric_sing");
	col_clear(pinfo->cinfo, COL_INFO);

	thalesauric_tree = tree;
	interfaceType = tvb_get_letohs(tvb, offset);

	//determine the header length
	switch (interfaceType)
	{
	case ZC_VOBC:
	case ZC_ZC:
	case VOBC_VOBC:
		//vital telegrams
		header_length = MSG_HEADER_LENGTH_VITAL_TELEGRAM;
		break;
	case ATS_VOBC:
	case ATS_ZC:
	case VOBC_TOD:
		//non-vital telegrams
		header_length = MSG_HEADER_LENGTH_NONVITAL_TELEGRAM;
		break;
	default:
		proto_tree_add_item(thalesauric_tree, hf_thalesauric_icddata, tvb, offset, tvb_reported_length(tvb) , ENC_NA);

	}
	if (tree == NULL)
		return 0;

	header_tree = proto_tree_add_subtree(thalesauric_tree, tvb, offset, tvb_reported_length(tvb), ett_thalesauric_header, NULL, "Thales Auric sing RSN/TSN Protocol");
	proto_tree_add_item(header_tree, hf_thalesauric_iType, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_iVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	proto_tree_add_item(header_tree, hf_thalesauric_telegramType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	receiverClass = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(header_tree, hf_thalesauric_receiverClass, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_receiverId, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	transmitterClass = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(header_tree, hf_thalesauric_transmitterClass, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_transmitterId, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_transmityear, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_transmitmonth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_transmitday, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_transmithour, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_transmitminute, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_transmitsecond, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_thalesauric_transmitmillisecond, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	rsn = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(header_tree, hf_thalesauric_rsn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	tsn = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(header_tree, hf_thalesauric_tsn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	if (header_length == MSG_HEADER_LENGTH_VITAL_TELEGRAM)
	{
		//TODO add RCC/LCC for vital telegrams
		proto_tree_add_item(header_tree, hf_thalesauric_rcclcc, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
	}
	proto_tree_add_item(header_tree, hf_thalesauric_dcn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	dataLength = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(header_tree, hf_thalesauric_datalength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	offset_data = offset;
	proto_tree_add_item(header_tree, hf_thalesauric_data, tvb, offset, dataLength, ENC_LITTLE_ENDIAN);
	offset += dataLength;
	proto_tree_add_item(header_tree, hf_thalesauric_firstcrc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	//proto_tree_add_item(thalesauric_tree, hf_thalesauric_icddata, tvb, offset, tvb_reported_length(tvb), ENC_NA);
	if (header_length == MSG_HEADER_LENGTH_VITAL_TELEGRAM)
	{
		//TODO add second crc for vital telegrams
		offset += 2;
	}
	switch (interfaceType)
	{
	case ATS_VOBC:
		if ((transmitterClass == TCLASS_VOBC) && (receiverClass == RCLASS_ATS))
		{
			strcpy(buficddisplay, VOBC2ATS);
			strcpy(colicddisplay, VOBC2ATS_COLINFODISPLAY);
		}
		else if ((transmitterClass == TCLASS_ATS) && (receiverClass == RCLASS_VOBC))
		{
			strcpy(buficddisplay, ATS2VOBC);
			strcpy(colicddisplay, ATS2VOBC_COLINFODISPLAY);
		}
		else
		{
			strcpy(buficddisplay, UNKNOWN);
		}
		sprintf(colinfodisplay, "%s IV:00 RSN=%-10dTSN=%-10d%d bytes", colicddisplay, rsn, tsn, dataLength);
		col_set_str(pinfo->cinfo, COL_INFO, colinfodisplay);
		body_tree = proto_tree_add_subtree(thalesauric_tree, tvb, offset_data, dataLength, ett_thalesauric_data, NULL, buficddisplay);
		
		break;
	case ZC_ZC:
	case ATS_ZC:
	case VOBC_TOD:
	case ZC_VOBC:
	case VOBC_VOBC:
		strcpy(buficddisplay, UNKNOWN);
		break;
	default:
		break;
	}
	if (body_tree != NULL)
	{
		if ((transmitterClass == TCLASS_VOBC) && (receiverClass == RCLASS_ATS))
		{
			processVOBC2ATSdata(body_tree, tvb, offset_data, dataLength);
		}
	}
	return  offset;
	//return  offset;
}

extern "C" void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

	foo_handle = new_create_dissector_handle(dissect_foo, proto_thalesauric);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}

