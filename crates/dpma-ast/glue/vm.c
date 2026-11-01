/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Voicemail API glue: walking the mailbox and message snapshots of
 * ast_vm_mailbox_snapshot_create(), whose layout (string fields and list
 * entries) is only known to C.
 *
 * Core Asterisk headers only (compiled into every module).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include "asterisk/app.h"
#include "asterisk/linkedlists.h"

int dpma_glue_vm_snapshot_total(const struct ast_vm_mailbox_snapshot *snapshot)
{
	return snapshot->total_msg_num;
}

int dpma_glue_vm_snapshot_folders(const struct ast_vm_mailbox_snapshot *snapshot)
{
	return snapshot->folders;
}

/*! The first message of folder list \a index (NULL when empty). */
const struct ast_vm_msg_snapshot *dpma_glue_vm_snapshot_first(const struct ast_vm_mailbox_snapshot *snapshot, int index)
{
	if (index < 0 || index >= snapshot->folders || !snapshot->snapshots) {
		return NULL;
	}
	return AST_LIST_FIRST(&snapshot->snapshots[index]);
}

const struct ast_vm_msg_snapshot *dpma_glue_vm_msg_next(const struct ast_vm_msg_snapshot *msg)
{
	return AST_LIST_NEXT(msg, msg);
}

/*!
 * The string fields of a message snapshot, in declaration order: msg_id,
 * callerid, callerchan, exten, origdate, origtime, duration, folder_name,
 * and flag.  Returns the message number.
 */
unsigned int dpma_glue_vm_msg_fields(const struct ast_vm_msg_snapshot *msg, const char *fields[9])
{
	fields[0] = msg->msg_id;
	fields[1] = msg->callerid;
	fields[2] = msg->callerchan;
	fields[3] = msg->exten;
	fields[4] = msg->origdate;
	fields[5] = msg->origtime;
	fields[6] = msg->duration;
	fields[7] = msg->folder_name;
	fields[8] = msg->flag;
	return msg->msg_number;
}
