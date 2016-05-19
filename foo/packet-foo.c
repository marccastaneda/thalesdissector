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

/* String constants for display */
#define VOBC2ATS											"VOBC2ATS"
#define ATS2VOBC											"ATS2VOBC"
#define VOBC2VOBC											"VOBC2VOBC"
#define VOBC2ZC												"VOBC2ZC"
#define ZC2VOBC												"ZC2VOBC"
#define UNKNOWN												"UNKNOWN"

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
static int hf_vobc2atsicd_trainrearffset					= -1;
static int hf_vobc2atsicd_trainfrontsegment					= -1;
static int hf_vobc2atsicd_trainfrontoffset					= -1;


static int ett_thalesauric									= -1;
static int ett_thalesauric_header							= -1;
static int ett_thalesauric_data								= -1;



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

int (*vobc2ats_func[])(proto_tree *tree, tvbuff_t *tvb, unsigned short offset) = 
	{ process_vobc2ats_vobcswversion, 
	  process_vobc2ats_vobcdbversion,
	  process_vobc2ats_trainid,
	  process_vobc2ats_vobcid,
	  process_vobc2ats_vobcactivestatus,
	  process_vobc2ats_numberofvehicles_vehiclelist,
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
	unsigned char	interfaceVersion;
	unsigned char	telegramType;
	unsigned short  receiverClass;
	unsigned short  receiverId;
	unsigned short  transmitterClass;
	unsigned short  transmitterId;
	int				offset					= 0;
	unsigned char   header_length			= 0;
	unsigned short	dataLength				= 0;
	unsigned short	offset_data				= 0;
	char			buficddisplay[15];


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "marc_thalesauric_sing");
	/* Clear out stuff in the info column */
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
	proto_tree_add_item(header_tree, hf_thalesauric_rsn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
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
		}
		else if ((transmitterClass == TCLASS_ATS) && (receiverClass == RCLASS_VOBC))
		{
			strcpy(buficddisplay, ATS2VOBC);
		}
		else
		{
			strcpy(buficddisplay, UNKNOWN);
		}
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

