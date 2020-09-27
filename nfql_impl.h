//
// Created by root on 05/02/2020.
//

#ifndef UNTITLED_NFQL_IMPL_H
#define UNTITLED_NFQL_IMPL_H

#endif //UNTITLED_NFQL_IMPL_H
int count_appearances(char * payload, char * word );
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data);
struct connector_data connect_and_listen() ;