#!/bin/bash

if [ "$#" -ne "2" ]; then
	echo "Usage: sshlab <user> <host>"
	exit
fi

USER=$1
HOST=$2

if [ "$USER" == "root" ]; then
	USER=gameadmin
	echo
	echo "===================================="
	echo
	echo "SSHing as root - you will connect now as 'gameadmin', but to get as root type:"
	echo
	echo "gameadmin@warzone:~$ sudo -s"
	echo \[sudo\] password for gameadmin: gameadmin
	echo
	echo "===================================="
	echo
fi

PASSES=("gameadmin:gameadmin"
		"lecture:lecture"

		"lab1C:lab01start"
		"lab2C:lab02start"
		"lab3C:lab03start"
		"lab4C:lab04start"
		"lab5C:lab05start"
		"lab6C:lab06start"
		"lab7C:lab07start"
		"lab8C:lab08start"
		"lab9C:lab09start"

		"lab1B:n0_str1ngs_n0_pr0bl3m"
		"lab1A:1337_3nCRyptI0n_br0"
		"lab1end:1uCKy_Gue55"

		"lab2B:1m_all_ab0ut_d4t_b33f"
		"lab2A:i_c4ll_wh4t_i_w4nt_n00b"
		"lab2end:D1d_y0u_enj0y_y0ur_cats?"

		"lab3B:th3r3_iz_n0_4dm1ns_0n1y_U!"
		"lab3A:wh0_n33ds_5h3ll3_wh3n_U_h4z_s4nd"
		"lab3end:sw00g1ty_sw4p_h0w_ab0ut_d3m_h0ps"
		
		"lab4B:bu7_1t_w4sn7_brUt3_f0rc34b1e!"
		"lab4A:fg3ts_d0e5n7_m4k3_y0u_1nv1nc1bl3"
		"lab4end:1t_w4s_ju5t_4_w4rn1ng"
		
		"lab5B:s0m3tim3s_r3t2libC_1s_3n0ugh"
		"lab5A:th4ts_th3_r0p_i_lik3_2_s33"
		"lab5end:byp4ss1ng_d3p_1s_c00l_am1rite"

		"lab6B:p4rti4l_0verwr1tes_r_3nuff"
		"lab6A:strncpy_1s_n0t_s0_s4f3_l0l"
		"lab6end:eye_gu3ss_0n_@ll_mah_h0m3w3rk"

		"lab7A:us3_4ft3r_fr33s_4re_s1ck"

		"lab8B:3v3ryth1ng_Is_@_F1l3"
		"lab8A:Th@t_w@5_my_f@v0r1t3_ch@11"
		"lab8end:H4x0r5_d0nt_N33d_m3t4pHYS1c5"

        "lab9A:1_th0uGht_th4t_w4rn1ng_wa5_l4m3"
		"lab9end:1_d1dNt_3v3n_n33d_4_Hilti_DD350"
)

FOUND=0
for P in "${PASSES[@]}" ; do
	U=${P%%:*}
	P=${P#*:}
	if [ "$U" == "$USER" ]; then
		printf "Logging as %s : %s on %s\n" "$U" "$P" "$HOST"
		FOUND=1
		sshpass -p "$P" ssh $USER@$HOST
	fi
done

if [ $FOUND -eq 0 ]; then
	echo "No credentials for that $USER user were defined yet."
fi
