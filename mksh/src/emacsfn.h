#if defined(EMACSFN_DEFNS)
__RCSID("$MirOS: src/bin/mksh/emacsfn.h,v 1.5 2010/07/17 22:09:33 tg Exp $");
#define FN(cname,sname,flags)	static int x_##cname(int);
#elif defined(EMACSFN_ENUMS)
#define FN(cname,sname,flags)	XFUNC_##cname,
#define F0(cname,sname,flags)	XFUNC_##cname = 0,
#elif defined(EMACSFN_ITEMS)
#define FN(cname,sname,flags)	{ x_##cname, sname, flags },
#endif

#ifndef F0
#define F0 FN
#endif

F0(abort, "abort", 0)
FN(beg_hist, "beginning-of-history", 0)
FN(cls, "clear-screen", 0)
FN(comment, "comment", 0)
FN(comp_comm, "complete-command", 0)
FN(comp_file, "complete-file", 0)
FN(comp_list, "complete-list", 0)
FN(complete, "complete", 0)
FN(del_back, "delete-char-backward", XF_ARG)
FN(del_bword, "delete-word-backward", XF_ARG)
FN(del_char, "delete-char-forward", XF_ARG)
FN(del_fword, "delete-word-forward", XF_ARG)
FN(del_line, "kill-line", 0)
FN(draw_line, "redraw", 0)
#ifndef MKSH_SMALL
FN(edit_line, "edit-line", XF_ARG)
#endif
FN(end_hist, "end-of-history", 0)
FN(end_of_text, "eot", 0)
FN(enumerate, "list", 0)
FN(eot_del, "eot-or-delete", XF_ARG)
FN(error, "error", 0)
FN(expand, "expand-file", 0)
#ifndef MKSH_SMALL
FN(fold_capitalise, "capitalize-word", XF_ARG)
FN(fold_lower, "downcase-word", XF_ARG)
FN(fold_upper, "upcase-word", XF_ARG)
#endif
FN(goto_hist, "goto-history", XF_ARG)
#ifndef MKSH_SMALL
FN(ins_string, "macro-string", XF_NOBIND)
#endif
FN(insert, "auto-insert", XF_ARG)
FN(kill, "kill-to-eol", XF_ARG)
FN(kill_region, "kill-region", 0)
FN(list_comm, "list-command", 0)
FN(list_file, "list-file", 0)
FN(literal, "quote", 0)
FN(meta1, "prefix-1", XF_PREFIX)
FN(meta2, "prefix-2", XF_PREFIX)
FN(meta_yank, "yank-pop", 0)
FN(mv_back, "backward-char", XF_ARG)
FN(mv_begin, "beginning-of-line", 0)
FN(mv_bword, "backward-word", XF_ARG)
FN(mv_end, "end-of-line", 0)
FN(mv_forw, "forward-char", XF_ARG)
FN(mv_fword, "forward-word", XF_ARG)
FN(newline, "newline", 0)
FN(next_com, "down-history", XF_ARG)
FN(nl_next_com, "newline-and-next", 0)
FN(noop, "no-op", 0)
FN(prev_com, "up-history", XF_ARG)
FN(prev_histword, "prev-hist-word", XF_ARG)
FN(search_char_back, "search-character-backward", XF_ARG)
FN(search_char_forw, "search-character-forward", XF_ARG)
FN(search_hist, "search-history", 0)
#ifndef MKSH_SMALL
FN(search_hist_dn, "search-history-down", 0)
FN(search_hist_up, "search-history-up", 0)
#endif
FN(set_arg, "set-arg", XF_NOBIND)
FN(set_mark, "set-mark-command", 0)
FN(transpose, "transpose-chars", 0)
FN(version, "version", 0)
#ifndef MKSH_SMALL
FN(vt_hack, "vt100-hack", XF_ARG)
#endif
FN(xchg_point_mark, "exchange-point-and-mark", 0)
FN(yank, "yank", 0)

#undef FN
#undef F0
#undef EMACSFN_DEFNS
#undef EMACSFN_ENUMS
#undef EMACSFN_ITEMS
