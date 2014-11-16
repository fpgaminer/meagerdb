meagerDB File Format
==========================

Simple, encrypted, lightweight.

Design Goals
------------
MeagerDB provides a simple, encrypted, ACID compliant database for embedded platforms.  First and foremost, it is designed for simplicity of code, so that it is easy to audit for security and hard to introduce bugs.  Since MeagerDB is built for embedded platforms it has a very small memory footprint, and doesn't use any memory allocations.  It is also ACID compliant, so it can be used in reliable systems.  All of these design goals are prioritized over read and write performance, as well as storage efficiency (for example, we pad journals to be one page each, wasting a lot of space, but making the code simple).



Major Concepts
--------------

The entire database is organized into fixed size chunks of data, called Pages.  Page size is configurable, but must be at least 256 bytes.  Page size will effect various performance characteristics.  Usually, it should be a multiple of the underlying storage's block/page size.

A meagerDB file always starts with:

 * Header
 * Encryption Parameters 1
 * Encryption Parameters 2
 * Journal 0
 * Journal 1

Each of those is padded to be a multiple of the Page Size.  The journals are always one page large.  Journal 0 is considered Page 0.  Therefore, the first row would start on Page 2.

A Row always begins at the beginning of a Page, and spans some integer multiple of Pages (at least 1).  A Row has a RowID, TableID, Page Count, and some data (Value).

A Row with a Page Count of 0 marks the end of the database.

A Row with a RowID of 0 marks an empty row.  Empty rows must have a Page Count of 1.

Journal 0 and Journal 1 are used to maintain database consistency during Insert, Update, and Delete operations.



ACID
----

MeagerDB is designed to provide Atomicity, Consistency, and Durability.  Isolation is not necessary, since meagerDB does not support concurrency.  There are no complex transactions; each SELECT, INSERT, UPDATE, and DELETE is its own separate transaction.

MeagerDB only provides the guarantee of ACID if the underlying filesystem abides by the usual POSIX requirements for `read`, `write`, and `sync`.  One important consideration is what happens in the event of a crash during `write` or `sync`.  MeagerDB will always write and read whole pages (except during create and open).  If a crash occurs during a page write, MeagerDB doesn't care what happens to data in that Page, or any other pages written to since the last `sync`.  But data in any untouched pages must remain unmodified.

For most systems, this is easy to achieve by setting meagerDB's Page Size to a multiple of the underlying disk's block/sector size.



Encryption
----------
Except for the Database Header and Encryption Parameters, all data is encrypted and MAC'd.  By default, the Threefish-512 block cipher is used for Encryption, HMAC-SHA-256 is used for Authentication, and SHA-256 is used for Hashing.  Encryption and Authentication use separate keys, 64-bytes each, and use tweaks.  The keys are stored in the Encryption Parameters Header, encrypted using a Derived Encryption Key.  The Derived Encryption Key is derived using the Password Salt and the Database Password.  The Encryption Parameters Header also includes a MAC, calculated using the Derived MAC Key, so that all data in the header is authenticated and the Database Keys are Encrypt-then-MAC.

Separating the Derived Keys from the Database Keys allows the Database Password to be changed without having to re-write the entire database.

Every Page is encrypted, and followed by a MAC of that Page (Encrypt-then-MAC).  Encryption Tweak is that Page's byte location in the database file.  A MAC tweak is also used, and is again the Page's byte location in the database file.  The MAC tweak is applied by appending the tweak to the end of the data to be MAC'd.  This makes the database more robust against scenarios where an attacker may try to move Pages around.



How to: Update Database Password
------------------------

The Database Password may be updated by creating a new Encryption Parameters (EP) block.  Overwrite the EP block that is not currently in use (the first non-valid DHEP).  Then erase the old EP.  This way, if the operation is halted at any moment, the database will not become corrupted.  The new password will only take effect when the operation is completed.



Columns
-------

The underlying database does not have a concept of columns.  Rows merely store a single, arbitrary length value.  A per-row Key-Value scheme is layered on top of the database using the `keyvalue.h/.c` module.  Applications may choose to roll their own schemes.



Journals
--------

There are two journals, Journal 0 and Journal 1.  They are used during Insert, Update, and Delete operations to keep the database consistent.  Each journal references a span of pages.

When opening the database, the journals should be checked and acted upon if valid.  If Journal 1 is valid, replace the specified range of pages with empty rows.  Then invalidate Journal 0 and Journal 1 (in that order).  If, only Journal 0 is valid, replace the specified range of pages with empty rows.  Then invalid both journals.  Both journals may, of course, be invalid when opening the database.



How to: Insert
------

Insertion is performed by finding, or creating, a span of empty rows big enough to hold the new row.  If creating new Pages, fill them with terminator rows (page count = 0).  Record this span in Journal 0.  Create the new row over the old, empty rows.  Erase Journal 0.

If Insert is not finished (power-loss, etc), the next time the database is opened the incomplete row will be removed during Journal recovery.



How to: Update
------

Update is performed by finding, or creating, a span of empty rows big enough to hold the updated row.  Record this span in Journal 0.  Create the updated row over the empty rows.  Now use Journal 1 to target the outdated row that we are updating.  Destroy the old row (convert into 1 or more empty rows).  Erase Journal 0.  Erase Journal 1.

If Update is not finished (power-loss, etc), the next time the database is opened the update may be rolled back by Journal recovery.  Depending on when the operation was interrupted, the Update may still complete.



How to: Delete
------

Delete is performed by recording the row in Journal 0.  Destroy the row.  Erase Journal 0.

If Delete is not finished (power-loss, etc), the next time the database is opened the delete will be completed by Journal recovery.



Key-Value Scheme
----------------
The built-in key-value scheme, allowing per row key-value stores, is implemented using a simple data format.  The row's value will consist of 0 or more Key-Value Chunks, one after the other.

Keys are of fixed length, 8 bytes by default.


Database Layout
---------------
   * Database Header (padded to multiple of Page)
   * Encryption Parameters (padded to multiple of Page)
   * Encryption Parameters (padded to multiple of Page)
   * Journal 0 (padded to multiple of Page)
   * Journal 1 (padded to multiple of Page)
   * Row(s)



Database Data Structures
------------------------

**All integers are stored little endian.**


####Database Header####
	* 8   string   "MEAGERDB"
	* 2   uint16   Version (0x0100)
	* 4   uint32   Page Size
	* 32  binary   Unique DB ID
	* 32  binary   Ciphersuite (e.g. Threefish-512:SHA-256:HMAC)
	* 32  binary   HASH of all data above in this structure
	* *   padding  Pad to multiple of Page Size


####Encryption Parameters####
	* 64  binary   Password Salt
	* 32  string   Key Derivation Function (e.g. "PBKDF2-HMAC-SHA-256")
	* 32  binary   Key Derivation Parameters (e.g. iteration count)
	* 128 binary   Encrypted Keys
	* 32  binary   MAC of DB Header HASH concat'd with all data above in this structure
	* 32  binary   HASH of all data above in this structure
	* *   padding  Pad to multiple of Page Size


####Journal####
	* 4   uint32   Page Start
	* 4   uint32   Page Count


####Row####
	* 4   uint32   Page Count
	* 4   uint32   Row ID  (0 for empty row)
	* 1   uint8    Table ID
	* 4   uint32   Value Length
	* *            Value Data


####Key-Value Chunk####
	* 8   binary   Key
	* 4   uint32   Value Length
	* *            Value Data
