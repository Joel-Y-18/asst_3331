Sender


Receiver



Notes
- Why have duplicate acks if corrupted packets are ignored? The answer is out of order segments arriving
- win_size is in bytes



Left to do:
    - Add in counting of statistics and ensure they are correct
    - Test on remaining text files
    - Go through entire assignment document to see if missed anything
    - Extensive checks
        - Receiver window size smaller than sender and a strange number (e.g. 793)
        - Sender has a very small window size
        - Am I sure that pipelining is actually working? What about the sender buffer being constrained by window size? Need to check
        - Write a script which diffs results and can have a lot of different settings for win_size etc.
    - Am I sure that triple dup acks work? Maybe test with manual tester
    - Am I sure that receiver does nothing on receiving a corrupted segment?
    - VALIDATE SEGMENT STRUCTURE WITH URPMON ON CSE
    - MUST CHANGE ELAPSED TIME TO START AT 0.00
