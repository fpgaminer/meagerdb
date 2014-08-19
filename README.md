MeagerDB
========


An encrypted database designed for low memory footprint and simplicity of code.
Designed for use on RAM-limited systems (microcontrollers).
Designed to optimize for code simplicity first, read performance second, and write performance third.


Maximum row size is `~2**32` (less due to row header).


There is no rigid table structure.  The underlying database only supports a single, unnamed chunk of data
per row.  Columns are implemented as per row key-value stores.  That functionality is provided in keyvalue.h.

Of course, the application is welcome to implement its own functionality layered on top of the underlying
database.  For example, rigid table structure could be enforced by having a schema table store schema data,
and writing a new key-value store that obeys the respective table's schema.


Searching the database can be accomplished manually using `mdb_walk`, or using the included search
functionality found in search.h.




See `meagerdb.h`, `keyvalue.h`, and `search.h` for an API reference.
See `database-specified.txt` for file format specification.

