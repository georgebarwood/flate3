//! RFC 1951 compression and de-compression.
//! 
//! flate3 is intended to be a high-performance alternative to the flate2 crate.
//!
//! It should compress slightly better than flate2. It uses multiple threads to compress faster. 
//!
//! # Example:
//! ```
//! let mut comp = flate3::Compressor::new();
//! let data = [ 1,2,3,4,1,2,3 ];
//! let cb : Vec<u8> = comp.deflate( &data );
//! println!( "compressed size={}", cb.len() );
//! let uc : Vec<u8> = flate3::inflate( &cb );
//! println!( "de-compressed size={}", uc.len() );
//! assert!( uc == &data );
//! ```

use crossbeam::{channel,channel::{Receiver,Sender}};

/// Compression options.
pub struct Options
{
  pub dynamic_block_size: bool,
  pub block_size: usize,
  pub matching: bool,
  pub probe_max: usize, 
  pub lazy_match: bool,
  pub match_channel_size: usize
}

/// Holds compression options and scoped thread pool.
pub struct Compressor
{
  pub options: Options,
  pub pool: scoped_threadpool::Pool
}

impl Compressor
{
  pub fn new() -> Compressor
  {
    Compressor
    { 
      options: Options
      { 
        dynamic_block_size: false, 
        block_size: 0x2000, 
        matching: true,
        probe_max: 10, 
        lazy_match: true,
        match_channel_size: 1000 
      },
      pool: scoped_threadpool::Pool::new(2)
    }
  }

  /// RFC 1951 compression.
  pub fn deflate( &mut self, inp: &[u8] ) -> Vec<u8>
  {
    let opt = &self.options;
    let mut out = BitStream::new( inp.len() );
    let ( mtx, mrx ) = channel::bounded( opt.match_channel_size ); // channel for matches
    let ( ctx, crx ) = channel::bounded( 1 ); // channel for checksum

    // Execute the match finding, checksum computation and block output in parallel using the scoped thread pool.
    self.pool.scoped( |s| 
    {
      if opt.matching { s.execute( || { find_matches( inp, mtx , &opt ); } ); }
      s.execute( || { ctx.send( adler32( &inp ) ).unwrap(); } );
      write_blocks( inp, mrx, crx, &mut out, &opt );
    } );

    out.bytes
  }
}

impl Default for Compressor 
{
  fn default() -> Self 
  {
    Self::new()
  }
}

fn write_blocks( inp: &[u8], mrx: Receiver<Match>, crx: Receiver<u32>, out: &mut BitStream, opt: &Options )
{
  out.write( 16, 0x9c78 );

  let len = inp.len();
  let mut block_start = 0; // start of next block
  let mut match_start = 0; // start of matches for next block
  let mut match_position = 0; // latest match position
  let mut mlist : Vec<Match> = Vec::new(); // list of matches
  loop
  {
    let mut block_size = len - block_start;
    let mut target_size = opt.block_size;
    if block_size > target_size { block_size = target_size; }

    let mut b = Block::new( block_start, block_size, match_start );
    if opt.matching{ match_position = get_matches( match_position, b.input_end, &mrx, &mut mlist ); }
    b.init( &inp, &mlist );

    if opt.dynamic_block_size // Investigate larger block size.
    {
      let mut bits = b.bit_size( out );
      loop
      {
        // b2 is a block which starts just after b, same size.
        block_size = len - b.input_end;
        if block_size == 0 { break; }
        target_size = b.input_end - b.input_start;
        if block_size > target_size { block_size = target_size; }
        let mut b2 = Block::new( b.input_end, block_size, b.match_end );
        match_position = get_matches( match_position, b2.input_end, &mrx, &mut mlist );
        b2.init( &inp, &mlist );

        // b3 covers b and b2 exactly as one block.
        let mut b3 = Block::new( b.input_start, b2.input_end - b.input_start, b.match_start );
        b3.init( &inp, &mlist );

        let bits2 = b2.bit_size( out );
        let bits3 = b3.bit_size( out ); 

        if bits3 > bits + bits2 
        {
          // tune_boundary( b, b2 ); 
          break; 
        }
        b = b3;
        bits = bits3;
      }
    }

    block_start = b.input_end;
    match_start = b.match_end;

    // println!( "block size={} start={} end={}", b.input_end - b.input_start, b.input_start, b.input_end );

    b.write( &inp, &mlist, out, block_start == len );
    if b.input_end == len { break; }
  }   
  out.pad(8);
  out.write( 32, crx.recv().unwrap() as u64 );
  out.flush();
}

/// Get matches up to position.
fn get_matches( mut match_position: usize, to_position: usize, mrx: &Receiver<Match>, mlist: &mut Vec<Match> ) -> usize
{
  while match_position < to_position 
  {
    match mrx.recv()
    {
      Ok( m ) => 
      {
        match_position = m.position;
        mlist.push( m );          
      },
      Err( _err ) => match_position = usize::MAX
    }
  }
  match_position
}

/// Checksum function per RFC 1950.
fn adler32( input: &[u8] ) -> u32
{
  let mut s1 = 1;
  let mut s2 = 0;
  for b in input
  {
    s1 = ( s1 + *b as u32 ) % 65521;
    s2 = ( s2 + s1 ) % 65521;
  }
  s2 * 65536 + s1   
}

//*******************************************************************************

struct Match
{
  pub position: usize,
  pub length: u16,
  pub distance: u16
}

fn find_matches( input: &[u8], output: Sender<Match>, opts: &Options )
{
  let len = input.len();
  if len > MIN_MATCH
  {
    let mut m = Matcher::new( len, opts );
    m.find( input, output );
  }
}

// RFC 1951 match ( LZ77 ) limits.
const MIN_MATCH : usize = 3; // The smallest match eligible for LZ77 encoding.
const MAX_MATCH : usize = 258; // The largest match eligible for LZ77 encoding.
const MAX_DISTANCE : usize = 0x8000; // The largest distance backwards in input from current position that can be encoded.
const ENCODE_POSITION : usize = MAX_DISTANCE + 1;

struct Matcher
{
  hash_shift: usize,
  hash_mask: usize,
  hash_table: Vec<usize>,
  probe_max: usize, 
  lazy_match: bool
}

impl Matcher
{
  fn new( len: usize, opts: &Options ) -> Matcher
  {
    let hash_shift = calc_hash_shift( len * 2 );
    let hash_mask = ( 1 << ( MIN_MATCH * hash_shift ) ) - 1;

    Matcher{
      hash_shift,
      hash_mask,
      hash_table: vec![ 0; hash_mask + 1 ],
      probe_max: opts.probe_max,
      lazy_match: opts.lazy_match
    } 
  }

  fn find( &mut self, input: &[u8], output: Sender<Match> ) // LZ77 compression.
  {
    let limit = input.len() - 2;

    let mut link : Vec<usize> = vec!(0; limit);

    let mut position = 0; // position in input.

    // hash will be hash of three bytes starting at position.
    let mut hash = ( ( input[ 0 ] as usize ) << self.hash_shift ) + input[ 1 ] as usize;

    while position < limit
    {
      hash = ( ( hash << self.hash_shift ) + input[ position + 2 ] as usize ) & self.hash_mask;        
      let mut hash_entry = self.hash_table[ hash ];
      self.hash_table[ hash ] = position + ENCODE_POSITION;

      if position >= hash_entry // Equivalent to position - ( hash_entry - ENCODE_POSITION ) > MAX_DISTANCE.
      {
         position += 1;
         continue;
      }
      link[ position ] = hash_entry;

      let ( mut match1, mut distance1 ) = self.best_match( input, position, hash_entry - ENCODE_POSITION, &mut link );
      position += 1;
      if match1 < MIN_MATCH { continue; }

      // "Lazy matching" RFC 1951 p.15 : if there are overlapping matches, there is a choice over which of the match to use.
      // Example: "abc012bc345.... abc345". Here abc345 can be encoded as either [abc][345] or as a[bc345].
      // Since a range typically needs more bits to encode than a single literal, choose the latter.
      while position < limit
      {
        hash = ( ( hash << self.hash_shift ) + input[ position + 2 ] as usize ) & self.hash_mask;          
        hash_entry = self.hash_table[ hash ];

        self.hash_table[ hash ] = position + ENCODE_POSITION;
        if position >= hash_entry { break; }
        link[ position ] = hash_entry;

        if !self.lazy_match { break; }

        let ( match2, distance2 ) = self.best_match( input, position, hash_entry - ENCODE_POSITION, &mut link );
        if match2 > match1 || match2 == match1 && distance2 < distance1
        {
          match1 = match2;
          distance1 = distance2;
          position += 1;
        }
        else { break; }
      }

      output.send( Match{ position:position-1, length:match1 as u16, distance:distance1 as u16 } ).unwrap();

      let mut copy_end = position - 1 + match1;
      if copy_end > limit { copy_end = limit; }

      position += 1;

      // Advance to end of copied section.
      while position < copy_end
      { 
        hash = ( ( hash << self.hash_shift ) + input[ position + 2 ] as usize ) & self.hash_mask;
        link[ position ] = self.hash_table[ hash ];
        self.hash_table[ hash ] = position + ENCODE_POSITION;
        position += 1;
      }
    }
  }

  // best_match finds the best match starting at position. 
  // old_position is from hash table, link [] is linked list of older positions.

  fn best_match( &mut self, input: &[u8], position: usize, mut old_position: usize, link: &mut Vec<usize> ) -> ( usize, usize )
  { 
    let mut avail = input.len() - position;
    if avail > MAX_MATCH { avail = MAX_MATCH; }

    let mut best_match = 0; let mut best_distance = 0;
    let mut key_byte = input[ position + best_match ];

    let mut probe_max: usize = self.probe_max;
    while probe_max > 0 
    { 
      if input[ old_position + best_match ] == key_byte
      {
        let mut mat = 0; 
        while mat < avail && input[ position + mat ] == input[ old_position + mat ]
        {
          mat += 1;
        }
        if mat > best_match
        {
          best_match = mat;
          best_distance = position - old_position;
          if best_match == avail || ! self.match_possible( input, position, best_match ) { break; }
          key_byte = input[ position + best_match ];
          probe_max = self.probe_max;
        }
      }
      old_position = link[ old_position ];
      if old_position <= position { break; }
      old_position -= ENCODE_POSITION;
      probe_max -= 1;
    }
    ( best_match, best_distance )
  }

  // match_possible is used to try and shorten the best_match search by checking whether 
  // there is a hash entry for the last 3 bytes of the next longest possible match.

  fn match_possible( &mut self, input: &[u8], mut position: usize, best_match: usize ) -> bool
  {
    position = ( position + best_match ) - 2;
    let mut hash = ( ( input[ position ] as usize ) << self.hash_shift ) + input[ position + 1 ] as usize;
    hash = ( ( hash << self.hash_shift ) + input[ position + 2 ] as usize ) & self.hash_mask;        
    position < self.hash_table[ hash ]
  }
} // end impl Matcher

fn calc_hash_shift( n: usize ) -> usize
{
  let mut p = 1;
  let mut result = 0;
  while n > p
  {
    p <<= MIN_MATCH;
    result += 1;
    if result == 6 { break; }
  }
  result
} 

//*******************************************************************************

/// Compression of RFC 1951 blocks.
struct Block
{
  pub input_start: usize, 
  pub input_end: usize,
  pub match_start: usize, 
  pub match_end: usize,
  lit: BitCoder, dist: BitCoder, len: LenCoder,
  len_symbols: usize,
  bits_computed: bool,
}
 
impl Block
{
  pub fn new( input_start: usize, input_count: usize, match_start: usize  ) -> Block
  {
    Block
    { 
      input_start, 
      input_end: input_start + input_count, 
      match_start,
      match_end: 0,
      lit:  BitCoder::new( 15, 288 ), 
      dist: BitCoder::new( 15, 32 ), 
      len:  LenCoder::new( 7, 19 ),
      len_symbols: 0,
      bits_computed: false,
    }
  }

  pub fn init( &mut self, input: &[u8], mlist: &[Match] )
  {
    // Counts how many times each symbol is used, also determines exact end of block.

    let mut position : usize = self.input_start;

    let mut mi = self.match_start; 
    loop // Through the applicable matches.
    {
      if mi == mlist.len() { break; }

      let mat = &mlist[ mi ];

      if mat.position >= self.input_end { break; }

      while position < mat.position
      {
        self.lit.used[ input[ position ] as usize ] += 1;
        position += 1;
      }

      // Compute match and distance codes.
      position += mat.length as usize;
      let mc = get_off_code( mat.length );
      let dc = get_dist_code( mat.distance );

      self.lit.used[ 257 + mc ] += 1;
      self.dist.used[ dc ] += 1;

      mi += 1;  
    }
    self.match_end = mi;

    while position < self.input_end
    {
      self.lit.used[ input[ position ] as usize ] += 1;
      position += 1;
    }

    self.input_end = position;
    self.lit.used[ 256 ] += 1; // End of block code.
  }

  pub fn bit_size( &mut self, output: &mut BitStream ) -> usize
  { 
    self.compute_bits( output );
    17 + 3 * self.len_symbols + self.len.bc.total() + self.lit.total() + self.dist.total()
  }

  pub fn write( &mut self, input: &[u8], mlist: &[Match], output: &mut BitStream, last: bool )
  {
    self.bit_size( output );
    self.lit.compute_codes();
    self.dist.compute_codes();
    self.len.bc.compute_codes();

    output.write( 1, if last {1} else {0} );
    output.write( 2, 2 ); // block type 2 = block encoded with dynamic Huffman codes.
    output.write( 5, ( self.lit.symbols - 257 ) as u64 ); 
    output.write( 5, ( self.dist.symbols - 1 ) as u64 ); 
    output.write( 4, ( self.len_symbols - 4 ) as u64 );

    for alp in &CLEN_ALPHABET[..self.len_symbols]
    {
      output.write( 3, self.len.bc.bits[ *alp as usize ] as u64 );
    }

    self.length_pass( true, output );
    self.put_codes( input, mlist, output );
    output.write( self.lit.bits[ 256 ], self.lit.code[ 256 ] as u64 ); // End of block code
  }

  fn put_codes( &mut self, input: &[u8], mlist: &[Match], output: &mut BitStream )
  {
    let mut position = self.input_start;

    for mat in &mlist[self.match_start .. self.match_end]
    {
      while position < mat.position
      {
        let ib = input[ position ] as usize;
        output.write( self.lit.bits[ ib ], self.lit.code[ ib ] as u64 );
        position += 1;
      }

      // Compute match and distance codes.
      position += mat.length as usize;
      let mc = get_off_code( mat.length );
      let dc = get_dist_code( mat.distance );

      // Output match info.
      output.write( self.lit.bits[ 257 + mc ], self.lit.code[ 257 + mc ] as u64 );
      output.write( MATCH_EXTRA[ mc ], (mat.length - MATCH_OFF[ mc ]) as u64 );
      output.write( self.dist.bits[ dc ], self.dist.code[ dc ] as u64 );
      output.write( DIST_EXTRA[ dc ], (mat.distance - DIST_OFF[ dc ]) as u64 );  
    }  

    while position < self.input_end
    {
      let ib = input[ position ] as usize;
      output.write( self.lit.bits[ ib ], self.lit.code[ ib ] as u64 );
      position += 1;
    }
  }

  fn compute_bits( &mut self, output: &mut BitStream )
  {
    if self.bits_computed { return; }      

    self.lit.compute_bits();
    self.dist.compute_bits();

    if self.dist.symbols == 0 { self.dist.symbols = 1; }

    // Compute length encoding.
    self.length_pass( false, output );
    self.len.bc.compute_bits();

    // The length codes are permuted before being stored ( so that # of trailing zeroes is likely to be more ).
    self.len_symbols = 19; 
    while self.len_symbols > 4 
      && self.len.bc.bits[ CLEN_ALPHABET[ self.len_symbols - 1 ] as usize ] == 0
    {
      self.len_symbols -= 1;
    }

    self.bits_computed = true;
  }

  fn length_pass( &mut self, last_pass: bool, output: &mut BitStream )
  {
    self.len.last_pass = last_pass; 
    self.len.encode_lengths( true, self.lit.symbols, &self.lit.bits, output );     
    self.len.encode_lengths( false, self.dist.symbols, &self.dist.bits, output );
  }

} // end impl Block

//*******************************************************************************

/// RFC 1951 length-limited Huffman coding.
struct BitCoder
{
  pub symbols: usize,  // Number of symbols to be encoded (input/output).
  pub used: Vec<u32>,  // Number of times each symbol is used in the block being encoded ( input ).
  pub bits: Vec<u8>,   // Number of bits used to encode each symbol ( output ).
  pub code: Vec<u16>,  // Code for each symbol (output).

  lim_bits: usize,  // Limit on code length ( 15 or 7 for RFC 1951 ).
  max_bits: usize,  // Maximum code length.
  left: Vec<u16>, right: Vec<u16>, // Tree storage.
}

impl BitCoder
{
  pub fn new( lim_bits: usize, symbols: usize ) -> BitCoder
  {
    BitCoder
    { 
      symbols,
      lim_bits, 
      max_bits: 0,
      used:  vec![0;symbols],
      bits:  vec![0;symbols],
      left:  vec![0;symbols],
      right: vec![0;symbols],
      code:  Vec::with_capacity( symbols ),
    }
  }

  pub fn compute_bits( &mut self ) // Compute bits from used.
  {
    // First try to compute a Huffman code.
    // Most of the time this succeeds, but sometime lim_bits is exceeeded in which case package_merge is used.

    // Tree nodes are encoded in a u64 using 32 bits for used count, 8 bits for the tree depth, 16 bits for the id.
    // Constants for accessing the bitfields.
    const USEDBITS : u8 = 32;
    const DEPTHBITS : u8 = 8;
    const IDBITS : u8 = 16;

    const USEDMASK : u64 = ( ( 1 << USEDBITS ) - 1 ) << ( IDBITS + DEPTHBITS );
    const DEPTHMASK : u64 = ( ( 1 << DEPTHBITS ) - 1 ) << IDBITS;
    const DEPTHONE : u64 = 1 << IDBITS;
    const IDMASK : u64 = ( 1 << IDBITS ) - 1;

    // First compute the number of bits to encode each symbol (self.bits), using a Heap.
    let mut heap = Heap::<u64>::new( self.symbols as usize );

    // Add the leaf nodes to the heap.
    for id in 0..self.symbols
    {
      let used = self.used[ id ];
      if used > 0 
      { 
        heap.add( ( used as u64 ) << ( IDBITS + DEPTHBITS ) | id as u64 );
      }
    }
    heap.make();

    // Construct the binary (non-leaf) nodes of the tree.
    let non_zero : usize = heap.count();
   
    match non_zero
    {
      0 => {}
      1 =>
      { 
        self.get_bits( ( heap.remove() & IDMASK ) as usize, 1 );
        self.max_bits = 1;
      } 
      _ =>
      {
        let mut node = 0;

        loop // Keep pairing the lowest frequency (least used) tree nodes.
        {
          let left = heap.remove(); 
          self.left[ node ] = ( left & IDMASK ) as u16;

          let right = heap.remove(); 
          self.right[ node ] = ( right & IDMASK ) as u16;

          // Extract depth of left and right nodes ( still shifted though ).
          let depth_left = left & DEPTHMASK;
          let depth_right = right & DEPTHMASK; 

          // New node depth is 1 + larger of depth_left and depth_right.
          let depth = DEPTHONE + std::cmp::max(depth_left,depth_right);

          // Add the new tree node to the heap, as above, Used | Depth | Id
          heap.insert( ( left + right ) & USEDMASK | depth | ( self.symbols + node ) as u64 );

          node += 1;

          if heap.count() < 2 { break }
        }
        
        let root = ( heap.remove() & ( DEPTHMASK | IDMASK ) ) as usize;
        self.max_bits = root >> IDBITS;
        if self.max_bits <= self.lim_bits
        {
          self.get_bits( root & IDMASK as usize, 0 );
        } else {
          self.max_bits = self.lim_bits;
          self.package_merge( non_zero );
        }
      }
    }

    // Reduce symbol count if there are unused trailing symbols.
    while self.symbols > 0 && self.bits[ self.symbols - 1 ] == 0
    { 
      self.symbols -= 1; 
    }
  }

  fn get_bits( &mut self, mut tree_node: usize, mut depth:u8 )
  {
    // Walk the tree reading off the number of bits to encode each symbol ( which is depth of tree ).
   
    if tree_node < self.symbols // node is a leaf.
    {
      self.bits[ tree_node ] = depth;
    } else {
      tree_node -= self.symbols;
      depth += 1;
      self.get_bits( self.left[ tree_node ] as usize, depth );
      self.get_bits( self.right[ tree_node ] as usize, depth );
    }
  }

  fn package_merge( &mut self, non_zero : usize )
  {
    // Tree nodes are encoded in a u64 using 16 bits for the id, 32 bits for Used.
    const IDBITS : i32 = 16;
    const IDMASK : u64 = ( 1 << IDBITS ) - 1;
    const USEDBITS : i32 = 32;
    const USEDMASK : u64 = ( ( 1 << USEDBITS ) - 1 ) << IDBITS;

    let tree_size = self.symbols * self.lim_bits;

    // Tree storage.
    self.left = vec![ 0; tree_size ];
    self.right = vec![ 0; tree_size ];

    // First create the leaf nodes for the tree and sort.
    let mut leaves : Vec<u64> = Vec::with_capacity( non_zero );

    for i in 0..self.symbols
    {
      let used = self.used[ i ];
      if used != 0 
      {
        leaves.push( (used as u64) << IDBITS | i as u64 );
      }
    }
    leaves.sort();

    let mut merged = Vec::<u64>::with_capacity( self.symbols );
    let mut next = Vec::<u64>::with_capacity( self.symbols );

    let mut package : usize = self.symbols; // Allocator for package (tree node) ids.

    for _i in 0..self.lim_bits
    {
      let mut lix = 0; // Index into leaves.
      let mut mix = 0; // Index into merged.
      let llen = leaves.len();
      let mlen = merged.len();
      let mut total = ( llen + mlen ) / 2;
      while total > 0
      {
        // Compute left.
        let mut left : u64;
        if mix < mlen
        {
          left = merged[ mix ];
          if lix < llen
          {
            let leaf = leaves[ lix ];
            if left < leaf { mix += 1; }
            else { left = leaf; lix += 1; }
          }
          else { mix += 1; }
        }
        else { left = leaves[ lix ]; lix += 1; }

        // Compute right.
        let mut right : u64;
        if mix < mlen
        {
          right = merged[ mix ];
          if lix < llen
          {
            let leaf = leaves[ lix ];
            if right < leaf { mix += 1; }
            else { right = leaf; lix += 1; }
          }
          else { mix += 1; }
        }
        else { right = leaves[ lix ]; lix += 1; }

        // Package left and right.  
        self.left[ package ] = ( left & IDMASK ) as u16;
        self.right[ package ] = ( right & IDMASK ) as u16;
        next.push( ( left + right ) & USEDMASK | package as u64 );        
        package += 1;
        total -= 1;
      }

      // Swap merged and next.
      std::mem::swap( &mut merged, &mut next );
      next.clear();
    }

    // Calculate the number of bits to encode each symbol.
    for node in merged
    {
      self.merge_get_bits( ( node & IDMASK ) as usize );
    }
  }

  fn merge_get_bits( &mut self, node : usize )
  {
    if node < self.symbols
    {
      self.bits[ node ] += 1;
    } else {
      self.merge_get_bits( self.left[ node ] as usize );
      self.merge_get_bits( self.right[ node ] as usize );
    }
  }

  pub fn total( &mut self ) -> usize
  {
    let mut result = 0;
    for i  in 0..self.symbols
    {
      result += self.used[ i ] as usize * self.bits[ i ] as usize;
    }
    result
  }

  pub fn compute_codes( &mut self )
  {
    // Code below is from RFC 1951 page 7.

    // bl_count[N] is the number of symbols encoded with N bits.
    let mut bl_count : Vec<u16> = vec![ 0; self.max_bits + 1 ];
    for sym in 0..self.symbols
    {
      bl_count[ self.bits[ sym ] as usize ] += 1; 
    }

    // Find the numerical value of the smallest code for each code length.
    let mut next_code : Vec<u16> = Vec::with_capacity( self.max_bits + 1 );
    let mut code : u16 = 0; 
    bl_count[ 0 ] = 0;
    next_code.push( 0 );
    for bc in bl_count
    {
      code = ( code + bc ) << 1;
      next_code.push( code );
    }

    // Calculate the result.
    for sym in 0..self.symbols
    {
      let length = self.bits[ sym ] as usize;      
      self.code.push( reverse( next_code[ length ] as usize, length ) as u16 );
      next_code[ length ] += 1;
    }
  }

} // end impl BitCoder

//*******************************************************************************

/// RFC 1951 encoding of lengths.
struct LenCoder
{
  pub bc: BitCoder,
  pub last_pass: bool, 
  previous_length: usize, zero_run: usize, repeat: usize,
}

impl LenCoder
{
  pub fn new( limit:usize, symbols:usize ) -> LenCoder
  {
    LenCoder
    {
      bc: BitCoder::new( limit, symbols ),
      last_pass: false,
      previous_length: 0,
      zero_run: 0,
      repeat: 0,
    }
  }

  // Run length encoding of code lengths - RFC 1951, page 13.

  pub fn encode_lengths( &mut self, is_lit: bool, count: usize, lengths: &[u8], output: &mut BitStream )
  {
    if is_lit 
    { 
      self.previous_length = 0; 
      self.zero_run = 0; 
      self.repeat = 0; 
    }
    for len in &lengths[..count]
    {
      let length = *len as usize;
      if length == 0
      { 
        if self.repeat > 0 { self.encode_repeat( output ); } 
        self.zero_run += 1; 
        self.previous_length = 0; 
      } else if length == self.previous_length {
        self.repeat += 1;
      } else { 
        if self.zero_run > 0 { self.encode_zero_run( output ); } 
        if self.repeat > 0 { self.encode_repeat( output ); }
        self.put_length( length, output );
        self.previous_length = length; 
      }
    }      
    if !is_lit 
    { 
      self.encode_zero_run( output ); 
      self.encode_repeat( output );
    }
  }

  fn put_length( &mut self, val: usize, output: &mut BitStream ) 
  { 
    if self.last_pass 
    {
      output.write( self.bc.bits[ val ], self.bc.code[ val ] as u64 ); 
    } else {   
      self.bc.used[ val ] += 1; 
    }
  }

  fn encode_repeat( &mut self, output: &mut BitStream )
  {
    while self.repeat > 0
    {
      if self.repeat < 3 
      { 
        self.put_length( self.previous_length, output ); 
        self.repeat -= 1; 
      } else { 
        let mut x = self.repeat; 
        if x > 6 { x = 6; } 
        self.put_length( 16, output ); 
        if self.last_pass
        { 
          output.write( 2, ( x - 3 ) as u64 ); 
        }
        self.repeat -= x;  
      }
    }
  }

  fn encode_zero_run( &mut self, output: &mut BitStream )
  {
    while self.zero_run > 0
    {
      if self.zero_run < 3 
      { 
        self.put_length( 0, output ); 
        self.zero_run -= 1; 
      }
      else if self.zero_run < 11 
      { 
        self.put_length( 17, output ); 
        if self.last_pass { output.write( 3, ( self.zero_run - 3 ) as u64 ); }
        self.zero_run = 0;  
      } else { 
        let mut x = self.zero_run; 
        if x > 138 { x = 138; } 
        self.put_length( 18, output ); 
        if self.last_pass { output.write( 7, ( x - 11 ) as u64 ); } 
        self.zero_run -= x; 
      }
    }
  }

} // end impl LenCoder

//*******************************************************************************

/// Output bit stream.
struct BitStream 
{
  buffer: u64,
  bits_in_buffer : u8,
  pub bytes: Vec<u8>,
}

impl BitStream
{
  pub fn new( capacity: usize ) -> BitStream
  {
    BitStream
    {
      buffer: 0,
      bits_in_buffer: 0,
      bytes: Vec::with_capacity( capacity )
    }
  }

  /// Write first n bits of value to BitStream, least significant bit is written first.
  /// Unused bits of value must be zero, i.e. value must be in range 0 .. 2^n-1.

  pub fn write( &mut self, mut n: u8, mut value: u64 )
  {
    if n + self.bits_in_buffer >= 64
    {
      self.save( value << self.bits_in_buffer | self.buffer );
      let space = 64 - self.bits_in_buffer;
      value >>= space;
      n -= space;
      self.buffer = 0;
      self.bits_in_buffer = 0;
    }
    self.buffer |= value << self.bits_in_buffer;
    self.bits_in_buffer += n;
  }

  /// Pad output with zero bits to n bit boundary where n is power of 2 in range 1,2,4..64, typically n=8.
  pub fn pad( &mut self, n: u8 )
  {
    let w = self.bits_in_buffer % n; 
    if w > 0 { self.write( n - w, 0 ); }
  }
  
  /// Flush bit buffer to bytes.
  pub fn flush( &mut self )
  {
    self.pad( 8 );
    let mut w = self.buffer;
    while self.bits_in_buffer > 0
    {
      self.bytes.push( ( w & 255 ) as u8 ); 
      w >>= 8;
      self.bits_in_buffer -= 8;
    }
  }

  fn save( &mut self, w: u64 )
  {
    self.bytes.extend_from_slice( &w.to_le_bytes() );
  }
} // end impl BitStream


//*******************************************************************************

/// Heap is an array organised so the smallest element can be efficiently removed.
struct Heap<T>{ vec: Vec<T> }

impl<T: Ord+Copy> Heap<T> // Ord+Copy means T can be compared and copied.
{
  /* Diagram showing numbering of tree elements.
           0
       1       2
     3   4   5   6

     The fundamental invariant is that a parent element is not greater than either child.
     H[N] <= H[N*2+1] and H[N] <= H[N*2+2] 
  */

  /// Create a new heap.
  pub fn new( capacity : usize ) -> Heap<T>
  {
    Heap{ vec: Vec::with_capacity( capacity ) }
  }

  /// Get the number of elements in the heap.
  pub fn count( & self ) -> usize
  {
    self.vec.len()
  }

  // add and make allow the heap to be efficiently initialised.

  /// Add an element to the array ( not yet a heap ).
  pub fn add( &mut self, x: T ) 
  {
    self.vec.push( x );
  }

  /// Make the array into a heap.
  pub fn make( &mut self )
  {
    // Initialise the heap by making every parent not greater than both it's children.

    let count = self.vec.len();
    let mut parent = count / 2;
    while parent > 0
    {
      parent -= 1; 
      let mut check = parent;
      // Move element at check down while it is greater than a child element.
      let elem : T = self.vec[ check ];
      loop
      {
        let mut child = check * 2 + 1; 
        if child >= count { break }
        let mut ce: T = self.vec[ child ];
        if child + 1 < count
        {
          let ce2: T = self.vec[ child + 1 ];
          if ce2 < ce { child += 1; ce = ce2; }
        }
        if ce >= elem { break }
        self.vec[ check ] = ce; 
        check = child;
      }
      self.vec[ check ] = elem;  
    }
  }

  /// Insert a new element into the heap.
  pub fn insert( &mut self, elem: T )
  {
    let mut child = self.vec.len();
    self.vec.push( elem );
    // Move the new element up the tree until it is not less than it's parent.
    while child > 0
    {
      let parent = ( child - 1 ) >> 1;
      let pe: T = self.vec[ parent ];
      if elem >= pe { break }
      self.vec[ child ] = pe;
      child = parent;
    }    
    self.vec[ child ] = elem;
  }

  /// Remove and return the smallest element.
  pub fn remove ( &mut self ) -> T
  {
    // The result is element 0.
    // The last element in the heap is moved to 0, then moved down until it is not greater than a child.
    let result = self.vec[ 0 ];
    let last = self.vec.len() - 1;
    let elem = self.vec[ last ];
    self.vec.pop();
    if last > 0 
    {
      let mut parent = 0;
      loop
      {
        let mut child = parent * 2 + 1; 
        if child >= last { break }
        let mut ce = self.vec[ child ];
        if child + 1 < last
        {
          let ce2 = self.vec[ child + 1 ];
          if ce2 < ce 
          { 
            child += 1; 
            ce = ce2; 
          }
        } 
        if ce >= elem { break }
        self.vec[ parent ] = ce; 
        parent = child;  
      }
      self.vec[ parent ] = elem;
    }
    result
  }
} // end impl Heap

//*******************************************************************************

/// RFC 1951 inflate ( de-compress ).

pub fn inflate( data: &[u8] ) -> Vec<u8>
{
  let mut input = InputBitStream::new( &data );
  let mut output = Vec::with_capacity( 2 * data.len() );
  let _flags = input.get_bits( 16 );
  loop
  {
    let last_block = input.get_bit();
    let block_type = input.get_bits( 2 );
    match block_type
    {
      2 => dyn_block( &mut input, &mut output ),
      1 => fixed_block( &mut input, &mut output ),
      0 => copy_block( &mut input, &mut output ),
      _ => ()
    }
    if last_block != 0 { break; }
  }  
  // Check the checksum.
  input.pad( 8 );
  let check_sum = input.get_bits(32) as u32;
  if adler32( &output ) != check_sum { panic!( "Bad checksum" ) }
  output
}

/// Decode block encoded with dynamic Huffman codes.
fn dyn_block( input: &mut InputBitStream, output: &mut Vec<u8> )
{
  let n_lit = 257 + input.get_bits( 5 );
  let n_dist = 1 + input.get_bits( 5 );
  let n_len = 4 + input.get_bits( 4 );

  // The lengths of the main Huffman codes (lit,dist) are themselves decoded by LenDecoder.
  let mut len = LenDecoder::new( n_len, input );
  let lit : BitDecoder = len.get_decoder( n_lit, input );
  let dist : BitDecoder = len.get_decoder( n_dist, input ); 

  loop
  {
    let x : usize = lit.decode( input );
    match x
    {
      0..=255 => output.push( x as u8 ),
      256 => break,
      _ => // LZ77 match code - replicate earlier output.
      {
        let mc = x - 257;
        let length = MATCH_OFF[ mc ] as usize + input.get_bits( MATCH_EXTRA[ mc ] as usize );
        let dc = dist.decode( input );
        let distance = DIST_OFF[ dc ] as usize + input.get_bits( DIST_EXTRA[ dc ] as usize );
        copy( output, distance, length ); 
      }
    }
  }
} // end do_dyn

/// Copy length bytes from output ( at specified distance ) to output.
fn copy( output: &mut Vec<u8>, distance: usize, mut length: usize )
{
  let mut i = output.len() - distance;
  while length > 0
  {
    output.push( output[ i ] );
    i += 1;
    length -= 1;
  }
}

/// Decode length-limited Huffman codes.
// For speed, a lookup table is used to compute symbols from the variable length codes ( rather than reading single bits ).
// To keep the lookup table small, codes longer than PEEK bits are looked up in two operations.
struct BitDecoder
{
  nsym: usize, // The number of symbols.
  bits: Vec<u8>, // The length in bits of the code that represents each symbol.
  maxbits: usize, // The length in bits of the longest code.
  peekbits: usize, // The bit length for the first lookup ( not greater than PEEK ).
  lookup: Vec<usize> // The table used to look up a symbol from a code.
}

/// Maximum number of bits for first lookup.
const PEEK : usize = 8; 

impl BitDecoder
{
  fn new( nsym: usize ) -> BitDecoder
  {
    BitDecoder 
    { 
      nsym,
      bits: vec![0; nsym],
      maxbits: 0,
      peekbits: 0,
      lookup: Vec::new()
    }
  }

  /// The main function : get a decoded symbol from the input bit stream.
  /// Codes of up to PEEK bits are looked up in a single operation.
  /// Codes of more than PEEK bits are looked up in two steps.
  fn decode( &self, input: &mut InputBitStream ) -> usize
  {
    let mut sym = self.lookup[ input.peek( self.peekbits ) ];
    if sym >= self.nsym
    {
      sym = self.lookup[ sym - self.nsym + ( input.peek( self.maxbits ) >> self.peekbits ) ];
    }  
    input.advance( self.bits[ sym ] as usize );
    sym
  }

  fn init_lookup( &mut self )
  {
    let mut max_bits : usize = 0; 
    for bp in &self.bits 
    { 
      let bits = *bp as usize;
      if bits > max_bits { max_bits = bits; } 
    }

    self.maxbits = max_bits;
    self.peekbits = if max_bits > PEEK { PEEK } else { max_bits };
    self.lookup.resize( 1 << self.peekbits, 0 );

    // Code below is from rfc1951 page 7.

    // bl_count is the number of codes of length N, N >= 1.
    let mut bl_count : Vec<usize> = vec![ 0; max_bits + 1 ];

    for sym in 0..self.nsym { bl_count[ self.bits[ sym ] as usize ] += 1; }

    let mut next_code : Vec<usize> = vec![ 0; max_bits + 1 ];
    let mut code = 0; 
    bl_count[ 0 ] = 0;

    for i in 0..max_bits
    {
      code = ( code + bl_count[ i ] ) << 1;
      next_code[ i + 1 ] = code;
    }

    for sym in 0..self.nsym
    {
      let length = self.bits[ sym ] as usize;
      if length != 0
      {
        self.setup_code( sym, length, next_code[ length ] );
        next_code[ length ] += 1;
      }
    }
  }

  fn setup_code( &mut self, sym: usize, len: usize, mut code: usize )
  {
    if len <= self.peekbits
    {
      let diff = self.peekbits - len;
      code <<= diff;
      for i in code..code + (1 << diff)
      {
        // lookup index is reversed to match InputBitStream::peek
        self.lookup[ reverse( i, self.peekbits ) ] = sym;
      }
    } else { // Secondary lookup required      
      let peekbits2 = self.maxbits - self.peekbits;

      // Split code into peekbits portion ( key ) and remainder ( code).
      let diff1 = len - self.peekbits;
      let key = reverse( code >> diff1, self.peekbits );
      code &= ( 1 << diff1 ) - 1;

      // Get the base for the secondary lookup.
      let mut base = self.lookup[ key ];
      if base == 0 // Secondary lookup not yet allocated for this key.
      {
        base = self.lookup.len();
        self.lookup.resize( base + ( 1 << peekbits2 ), 0 );
        self.lookup[ key ] = self.nsym + base;
      } else {
        base -= self.nsym;
      }

      // Set the secondary lookup values.
      let diff = self.maxbits - len;
      code <<= diff;
      for i in code..code + (1<<diff)
      { 
        self.lookup[ base + reverse( i, peekbits2 ) ] = sym;
      }
    }    
  }
} // end impl BitDecoder

/// Decodes an array of lengths, returning a new BitDecoder.  
/// There are special codes for repeats, and repeats of zeros, per RFC 1951 page 13.
struct LenDecoder
{
  plenc: u8, // previous length code ( which can be repeated )
  rep: usize,   // repeat
  bd: BitDecoder
}

impl LenDecoder
{
  fn new(  n_len: usize, input: &mut InputBitStream ) -> LenDecoder
  {
    let mut result = LenDecoder { plenc: 0, rep:0, bd: BitDecoder::new( 19 ) };

    // Read the array of 3-bit code lengths (used to encode the main code lengths ) from input.
    for i in CLEN_ALPHABET.iter().take( n_len )
    { 
      result.bd.bits[ *i as usize ] = input.get_bits(3) as u8; 
    }
    result.bd.init_lookup();
    result
  }

  fn get_decoder( &mut self, nsym: usize, input: &mut InputBitStream ) -> BitDecoder
  {
    let mut result = BitDecoder::new( nsym );
    let bits = &mut result.bits;
    let mut i = 0;
    while self.rep > 0 { bits[ i ] = self.plenc; i += 1; self.rep -= 1; }
    while i < nsym
    { 
      let lenc = self.bd.decode( input ) as u8;
      if lenc < 16 
      {
        bits[ i ] = lenc; 
        i += 1; 
        self.plenc = lenc; 
      } else {
        if lenc == 16 { self.rep = 3 + input.get_bits(2); }
        else if lenc == 17 { self.rep = 3 + input.get_bits(3); self.plenc=0; }
        else if lenc == 18 { self.rep = 11 + input.get_bits(7); self.plenc=0; } 
        while i < nsym && self.rep > 0 { bits[ i ] = self.plenc; i += 1; self.rep -= 1; }
      }
    }
    result.init_lookup();
    result
  }
} // end impl LenDecoder

/// For reading bits from input array of bytes.
struct InputBitStream<'data>
{
  data: &'data [u8], // Input data.
  pos: usize, // Position in input data.
  buf: usize, // Bit buffer.
  got: usize, // Number of bits in buffer.
}

impl <'data> InputBitStream<'data>
{
  fn new( data: &'data [u8] ) -> InputBitStream
  {
    InputBitStream { data, pos: 0, buf: 0, got: 0 }
  } 

  // Get n bits of input ( but do not advance ).
  fn peek( &mut self, n: usize ) -> usize
  {
    while self.got < n
    {
      // Not necessary to check index, considering adler32 checksum is 32 bits.
      self.buf |= ( self.data[ self.pos ] as usize ) << self.got;
      self.pos += 1;
      self.got += 8;
    }
    self.buf & ( ( 1 << n ) - 1 )
  }

  // Advance n bits.
  fn advance( &mut self, n:usize )
  { 
    self.buf >>= n;
    self.got -= n;
  }

  // Get a single bit.
  fn get_bit( &mut self ) -> usize
  {
    if self.got == 0 { self.peek( 1 ); }
    let result = self.buf & 1;
    self.advance( 1 );
    result
  }

  // Get n bits of input.
  fn get_bits( &mut self, n: usize ) -> usize
  { 
    let result = self.peek( n );
    self.advance( n );
    result
  }

  // Get n bits of input, reversed.
  fn get_huff( &mut self, mut n: usize ) -> usize 
  { 
    let mut result = 0; 
    while n > 0
    { 
      result = ( result << 1 ) + self.get_bit(); 
      n -= 1;
    }
    result
  }

  // Move to n-bit boundary ( n a power of 2 ).
  fn pad( &mut self, n: usize )
  {  
    self.advance( self.got % n );
  }
} // end impl InputBitStream

/// Reverse a string of n bits.
fn reverse( mut x:usize, mut n: usize ) -> usize
{ 
  let mut result: usize = 0; 
  while n > 0
  {
    result = ( result << 1 ) | ( x & 1 ); 
    x >>= 1; 
    n -= 1;
  } 
  result
} 

/// Copy uncompressed block to output.
fn copy_block( input: &mut InputBitStream, output: &mut Vec<u8> )
{
  input.pad( 8 ); // Move to 8-bit boundary.
  let mut n = input.get_bits( 16 );
  let _n1 = input.get_bits( 16 );
  while n > 0 { output.push( input.data[ input.pos ] ); n -= 1; input.pos += 1; }
}

/// Decode block encoded with fixed (pre-defined) Huffman codes.
fn fixed_block( input: &mut InputBitStream, output: &mut Vec<u8> ) // RFC1951 page 12.
{
  loop
  {
    // 0 to 23 ( 7 bits ) => 256 - 279; 48 - 191 ( 8 bits ) => 0 - 143; 
    // 192 - 199 ( 8 bits ) => 280 - 287; 400..511 ( 9 bits ) => 144 - 255
    let mut x = input.get_huff( 7 ); // Could be optimised. 
    if x <= 23 
    { 
      x += 256; 
    } else {
      x = ( x << 1 ) + input.get_bit();
      if x <= 191 { x -= 48; }
      else if x <= 199 { x += 88; }
      else { x = ( x << 1 ) + input.get_bit() - 256; }
    }

    match x
    {
      0..=255 => { output.push( x as u8 ); }
      256 => { break; } 
      _ => // 257 <= x && x <= 285 
      { 
        x -= 257;
        let length = MATCH_OFF[x] as usize + input.get_bits( MATCH_EXTRA[ x ] as usize );
        let dcode = input.get_huff( 5 );
        let distance = DIST_OFF[dcode] as usize + input.get_bits( DIST_EXTRA[dcode] as usize );
        copy( output, distance, length );
      }
    }
  }
} // end fixed_block

/// Binary search macro.
/// Parameters are variable we are searching for ($x) and list of numbers ( or anything comparable with $x ).
// Rust macro features used ( per https://doc.rust-lang.org/1.7.0/book/macros.html )
//   $ is used to define match variables.
//   expr stands for expression
//   tt stands for token tree
//   * means zero or more repetitions.
//   + means one or more repetitions.
//   @ is used for labelling sub-macros.
macro_rules! find_index 
{
  // Initial rule, invoke step A with count set to zero and empty list of neps.
  // nep stands for number-expression-pair { number; expression }
  ( $x:ident, [ $($num:expr),+ ] ) => 
  {
    find_index!( @A, $x, [ $($num)+ ], 0, [] )
  };

  // Step A: pair the numbers with values generated by counting from 0.
  // Parameters are x, input list of numbers, count, output list of neps.
 
  // If the input list of numbers is not empty..
  ( @A, $x:ident, [ $firstnum:tt $($more_nums:expr)* ], $count:expr, [ $($out_nep:tt)* ] ) => 
  {
    // .. append nep {$firstnum; $count} to the output list.
    find_index!( @A, $x, [ $($more_nums)*], $count+1, [ $($out_nep)* {$firstnum; $count} ] )
  };

  // If the input list of numbers is empty, step A is complete, move to step B.
  ( @A, $x:ident, [], $count:expr, $neps:tt ) => 
  {
    find_index!( @B, $x, $neps, [] )
  };

  // If the initial parameters are (say) x and [5,7,9,13] then the step A evaluates to
  // find_index! ( @ B, x, [], [{(5); 0} [(7); 0 + 1] {(9); 0 + 1 + 1} {(13); 0 + 1 + 1 + 1}] )
  // or simplified:
  // find_index! ( @ B, x, [], [ {5; 0} {7; 1} {9; 2} {13; 3} ] )

  // Step B: generate the  final binary search expression from the {number; expr} pairs.
  // Parameters are x, input list, output list.
  // We keep pairing neps in the input list, putting them in output list.
  // When the input is exhausted, the output becomes the input for the next iteration.
  // Step B terminates when the input list is a single nep, and the output list is empty.

  // Input list has two neps ..
  ( @B, $x:ident, [ { $num1:expr; $exp1:expr } { $num2:expr; $exp2:expr } $($more_nep:tt)* ], [$($out_nep:tt)*] ) => 
  {
    // .. append a nep to output, consisting of first number and comparison of x with second number, choosing $exp1 or $exp2.
    find_index!( @B, $x, [ $($more_nep)* ], [ $($out_nep)* { $num1; ( if $x < $num2 {$exp1} else {$exp2} ) } ] )
  };

  // Input list is empty ..
  ( @B, $x:ident, [], $neps:tt ) => 
  {
    // .. swap input and output, start next iteration in step B.
    find_index!( @B, $x, $neps, [] )
  };

  // Input list is single nep, append it to output ( which is not empty since + means 1 or more repetitions ).
  ( @B, $x:ident, [ {$num:expr; $exp:expr} ], [ $($out_nep:tt)+ ] ) => 
  {
    find_index!( @B, $x, [], [ $($out_nep)+ {$num; $exp} ] )
  };

  // Input list is single nep, output is empty, we are done.
  ( @B, $x:ident, [ {$num:expr; $final_exp:expr} ], [] ) => 
  {
    $final_exp
  };
}

// RFC 1951 constants.

static CLEN_ALPHABET : [u8; 19] = [ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 ];

const MATCH_OFF : [u16; 29] = [ 3,4,5,6, 7,8,9,10, 11,13,15,17, 19,23,27,31, 35,43,51,59, 
  67,83,99,115,  131,163,195,227, 258 ];

static MATCH_EXTRA : [u8; 29] = [ 0,0,0,0, 0,0,0,0, 1,1,1,1, 2,2,2,2, 3,3,3,3, 4,4,4,4, 5,5,5,5, 0 ];

static DIST_OFF : [u16; 30] = [ 1,2,3,4, 5,7,9,13, 17,25,33,49, 65,97,129,193, 257,385,513,769, 
  1025,1537,2049,3073, 4097,6145,8193,12289, 16385,24577 ];

static DIST_EXTRA : [u8; 30] = [ 0,0,0,0, 1,1,2,2, 3,3,4,4, 5,5,6,6, 7,7,8,8, 9,9,10,10, 11,11,12,12, 13,13 ];

fn get_dist_code( x: u16 ) -> usize {
  find_index!( x, [ 1,2,3,4, 5,7,9,13, 17,25,33,49, 65,97,129,193, 
    257,385,513,769, 1025,1537,2049,3073, 4097,6145,8193,12289, 16385,24577 ] )
}

// Requires rust 1.46.
const fn get_off_code( x: u16 ) -> usize {
  const LAST : usize = MATCH_OFF.len() - 1;
  const MAX : usize = MATCH_OFF[ LAST ] as usize;
  const LUT : [ u8; MAX ] = {
    let mut lut : [ u8; MAX ] = [ 0; MAX ];
    let mut i_val = 0;
    let mut i_lut = 0;
    while i_lut < lut.len() {
      while MATCH_OFF[ i_val + 1 ] <= i_lut as u16 {
        i_val += 1;
      }
      lut[ i_lut ] = i_val as u8;
      i_lut += 1;
    }
    lut
  };
  if x as usize >= MAX {
    LAST
  } else {
    LUT[ x as usize ] as usize
  }
}    

// Rest is commented out alternative methods for get_off_code and get_dist_code.

/* use if rust version is pre 1.46
fn get_off_code( x: u16 ) -> usize {
  find_index!( x, [ 3,4,5,6, 7,8,9,10, 11,13,15,17, 19,23,27,31, 
    35,43,51,59,  67,83,99,115,  131,163,195,227, 258 ] )
}
*/

/* Method using standard library binary search.
fn get_off_code( x:u16 ) -> usize
{
  match MATCH_OFF.binary_search( &x ) {
    Ok( c ) => c,
    Err( c ) => c - 1
  }
}
*/

/* Arithmetic method : not as fast as binary search.
fn get_dist_code( mut x0:u16 ) -> usize
{
  x0 -= 1;
  let x = x0 as usize;
  let mut bits = 16 - x0.leading_zeros() as usize;
  if bits < 3 { 
    x 
  } else { 
    bits -= 1;
    ( x + ( ( bits << 1 ) << ( bits - 1 ) ) - ( 1 << bits ) ) >> ( bits - 1 ) 
  }
}
*/
