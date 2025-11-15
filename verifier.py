import subprocess 
import time

## Params ##
sender_port = 12000
receiver_port = 14000

text_file = 'rfc793.txt'

max_win_snd = 1000
max_win_rcv = 1000
rto = 50

flp = 0.5
rlp = 0.5
fcp = 0
rcp = 0

## Code ##

sender_file = f'input/{text_file}'
receiver_file = f'output/{text_file}'

sender_args = ['python3', 'sender.py', 
               str(sender_port), str(receiver_port), 
               sender_file, 
               str(max_win_snd), str(rto), 
               str(flp), str(rlp), str(fcp), str(rcp)]
receiver_args = ['python3', 'receiver.py',
                 str(receiver_port), str(sender_port),
                 receiver_file,
                 str(max_win_rcv)]

print("Running sender and receiver.")
rcv_proc = subprocess.Popen(' '.join(receiver_args), shell=True, stdout=subprocess.DEVNULL)
time.sleep(0.1)
send_proc = subprocess.Popen(' '.join(sender_args), shell=True, stdout=subprocess.DEVNULL)
send_proc.wait()
rcv_proc.wait()
print("Execution complete.")

difference_proc = subprocess.run(f'diff {sender_file} {receiver_file}', shell=True, capture_output=True, text=True)
if difference_proc.returncode != 0:
    print("Files are not identical. Differences: ")
    print(difference_proc.stdout)
else:
    print("Files are identical.")

input("Go for statistics")
print("Comparing statistics")

with open('sender_log.txt') as sl, open('receiver_log.txt') as rl:
    sl_lines = sl.read().splitlines()[-12:]
    rl_lines = rl.read().splitlines()[-8:]
    
    def extract_stats(lines):
        return [int(line.split(':')[1].strip()) for line in lines]

    sl_stats = extract_stats(sl_lines)
    rl_stats = extract_stats(rl_lines)

    snd_orig_bytes, snd_tot_bytes, snd_orig_segs, snd_tot_segs = sl_stats[0:4]
    snd_timeouts, snd_fast_retransmits, snd_dup_acks_received = sl_stats[4:7]
    snd_cor_acks_discarded, plc_fwd_drp, plc_fwd_cor, plc_rev_drp, plc_rev_cor = sl_stats[7:12]

    rcv_orig_bytes, rcv_tot_bytes, rcv_orig_segs, rcv_tot_segs = rl_stats[0:4]
    rcv_cor_segs_discarded, rcv_dup_segs_received, rcv_tot_acks_sent, rcv_dup_acks_send = rl_stats[4:8]
    
    ## Checks ##
    check_fail = False
    def check(eval, msg):
        global check_fail
        if not eval:
            print(msg)
            check_fail = True
    
    check(snd_orig_bytes == rcv_orig_bytes, 'snd and rcv orig bytes mismatch')
    with open(sender_file) as sndf:
        check(snd_orig_bytes == len(sndf.read()), 'snd orig bytes sent not equal to file length')
    check(snd_orig_segs == rcv_orig_segs, 'snd and rcv orig segs mismatch')
    check(snd_timeouts + snd_fast_retransmits == snd_tot_segs - snd_orig_segs, 'timeout or fast retransmit counters are off')
    check(snd_cor_acks_discarded == plc_rev_cor, 'sender did not discard some corrupted packets')
    check(rcv_cor_segs_discarded == plc_fwd_cor, 'receiver did not discard some corrupted packets')
    
    if check_fail:
        print("Checks failed. The original stats are below.")
        print("Sender:\n  " + '  \n'.join(sl_lines))
        print("Receiver:\n  " + '  \n'.join(rl_lines))
    else:
        print("Checks passed.")
    

