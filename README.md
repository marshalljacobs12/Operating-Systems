# CSCI-350
Operating Systems

This repo contains my solutions to the 4 projects in CSCI 350 Operating Systems at USC, taught by Professor Mark Redekopp. The course website from Summer 2018 is archived here: http://bits.usc.edu/cs350/index.html

The four assignments for this class involved implementing different parts of a simple operating system framework for the 80x86 architecture called Pintos. It was created at Stanford University by Ben Pfaff in 2004, and full documentation of the source code and projects can be found at https://web.stanford.edu/class/cs140/projects/pintos/pintos.html#SEC_Top.

A brief description of each project is listed below. For more detailed project descriptions, see the project descriptions in each project's folder.

Project 1: Threads
--> This project focuses on extending the functionality of the initial thread system. Furthermore, this project involves implementing priority donation as the scheduling algorithm. (Note: My class did not require me to implement the advanced scheduler in part 3)

Project 2: User Programs
--> This project involves implementing system calls to enhance the functionality of user programs. In project 1, all code was integrated into the kernel, and adding system calls provides an interface for user processes to interface with the kernel in a protected manner.

Project 3: Virtual Memory
--> This project involves implementing a virtual memory system. Adding virtual memory removes the constraint of limited machine memory and thus allows Pintos to run larger programs.

Project 4: File System
--> This project involves implementing an improved file system in Pintos. The new file system removes the limitations of Pintos' original file system which could only store fixed-size files within consecutive sectors.
