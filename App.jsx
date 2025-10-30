import React, { useState, useEffect, lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useNavigate, useParams, useLocation } from 'react-router-dom';
import { t } from './src/i18n.js';
import { makeSecureRequest } from './src/csrf.js';
import { getToken, setToken, getUser, setUser, clearAuth } from './src/storage.js';

// Lazy load heavy components
const ProductDetailPage = lazy(() => Promise.resolve({ default: ProductDetailPageComponent }));
const CheckoutPage = lazy(() => Promise.resolve({ default: CheckoutPageComponent }));
const AdminPanel = lazy(() => Promise.resolve({ default: AdminPanelComponent }));
const TrackOrderPage = lazy(() => Promise.resolve({ default: TrackOrderPageComponent }));
const ProfilePage = lazy(() => Promise.resolve({ default: ProfilePageComponent }));
const OrderStatusPage = lazy(() => Promise.resolve({ default: OrderStatusPageComponent }));
const WishlistPage = lazy(() => Promise.resolve({ default: WishlistPageComponent }));

// API Base URL
const API_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:3001').replace(/\/$/, '');

// Main App Component
function App() {
  const [user, setUser] = useState(null);
  const [cart, setCart] = useState([]);

  // Update cart item quantity
  const updateCartQuantity = (productId, newQuantity) => {
    let newCart;
    if (newQuantity <= 0) {
      newCart = cart.filter(item => item._id !== productId);
    } else {
      newCart = cart.map(item => 
        item._id === productId ? { ...item, quantity: newQuantity } : item
      );
    }
    setCart(newCart);
    localStorage.setItem('cart', JSON.stringify(newCart));
  };
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true); // Set initial loading to true
  const [wishlistItems, setWishlistItems] = useState([]);
  const [wishlistProducts, setWishlistProducts] = useState([]); // New state for full product objects
  const [notification, setNotification] = useState(null);
  const [isInitialLoad, setIsInitialLoad] = useState(true);

  // Load user from localStorage on app start
  useEffect(() => {
    const token = getToken();
    const userData = getUser();
    const savedCart = localStorage.getItem('cart');
    
    if (token && userData) {
      // Validate token by making a test API call
      validateToken(token, userData);
    } else if (savedCart) {
      setCart(JSON.parse(savedCart));
      setIsInitialLoad(false);
    } else {
      setIsInitialLoad(false);
    }
    // Initial product fetch is now handled inside the App component
    // to prevent re-fetching on every component mount that uses the hook.
    // The hook can be used in other components for accessing the products.
    fetchProducts().then(() => setLoading(false));
  }, []);

  // Validate token and set user
  const validateToken = async (token, userData) => {
    try {
      // Skip validation if we have valid user data and token exists
      if (token && userData && userData.email) {
        setUser(userData);
        setIsInitialLoad(false);
        // Fetch user data in background without blocking UI
        fetchWishlist().catch(console.error);
        fetchCart().catch(console.error);
        return;
      }
      
      // Only validate if we don't have complete user data
      const response = await fetch(`${API_BASE}/api/profile`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const profileData = await response.json();
        const userObj = { 
          id: profileData._id, 
          name: profileData.name, 
          email: profileData.email, 
          phone: profileData.phone 
        };
        setUser(userObj);
        setUser(userObj);
        fetchWishlist();
        fetchCart();
      } else {
        clearAuth();
        setUser(null);
        setCart([]);
      }
    } catch (error) {
      console.error('Token validation error:', error);
      // Don't clear auth on network errors, just set user from stored data
      if (userData && userData.email) {
        setUser(userData);
      }
    }
    setIsInitialLoad(false);
  };

  // Sync cart with server when cart changes for logged-in users
  useEffect(() => {
    if (user && !isInitialLoad && cart.length >= 0) {
      syncCart(cart);
    }
  }, [cart, user, isInitialLoad]);

  const fetchWishlist = async () => {
    try {
      const token = getToken();
      if (!token) return;
      
      const response = await fetch(`${API_BASE}/api/wishlist`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        console.log('Wishlist data:', data); // Debug log
        if (Array.isArray(data)) { // The API now returns an array of product objects
          setWishlistProducts(data);
          // Keep wishlistItems (IDs) in sync for quick lookups (e.g., heart icon)
          setWishlistItems(data.map(item => item._id));
        }
      }
    } catch (error) {
      console.error('Error fetching wishlist:', error);
    }
  };

  const fetchCart = async () => {
    try {
      const token = getToken();
      if (!token) {
        setIsInitialLoad(false);
        return;
      }
      
      const response = await fetch(`${API_BASE}/api/cart`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setCart(data.cart || []);
        localStorage.setItem('cart', JSON.stringify(data.cart || []));
        setIsInitialLoad(false);
      }
    } catch (error) {
      console.error('Error fetching cart:', error);
      setIsInitialLoad(false);
    }
  };

  const syncCart = async (cartData) => {
    try {
      await makeSecureRequest(`${API_BASE}/api/cart`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ cart: cartData })
      });
    } catch (error) {
      console.error('Error syncing cart:', error);
    }
  };

  // Fetch all products with caching
  const fetchProducts = async () => {
    const cached = localStorage.getItem('products_cache');
    const cacheTime = localStorage.getItem('products_cache_time');
    
    if (cached && cacheTime && Date.now() - parseInt(cacheTime) < 300000) {
      setProducts(JSON.parse(cached));
      return;
    }
    
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/products`);
      if (response.ok) {
        const data = await response.json();
        setProducts(data || []);
        localStorage.setItem('products_cache', JSON.stringify(data || []));
        localStorage.setItem('products_cache_time', Date.now().toString());
      } else {
        console.error('Failed to fetch products:', response.status);
        setProducts([]);
      }
    } catch (error) {
      console.error('Error fetching products:', error);
      setProducts([]);
    }
    setLoading(false);
  };

  // Add item to cart
  const addToCart = (product) => {
    const existingItem = cart.find(item => item._id === product._id);
    let newCart;
    if (existingItem) {
      newCart = cart.map(item => 
        item._id === product._id 
          ? { ...item, quantity: item.quantity + 1 }
          : item
      );
    } else {
      newCart = [...cart, { ...product, quantity: 1 }];
    }
    setCart(newCart);
    localStorage.setItem('cart', JSON.stringify(newCart));
    
    // Show notification
    setNotification({ message: 'Added to cart', product: product.name });
    setTimeout(() => setNotification(null), 3000);
  };

  // Remove item from cart
  const removeFromCart = (productId) => {
    const newCart = cart.filter(item => item._id !== productId);
    setCart(newCart);
    localStorage.setItem('cart', JSON.stringify(newCart));
  };

  // Login function
  const login = async (email, password) => {
    try {
      const response = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      if (response.status === 429) {
        alert('Too many login attempts. Please wait 15 minutes and try again.');
        return false;
      }
      
      const data = await response.json();
      
      if (response.ok) {
        setToken(data.token);
        setUser(data.user);
        
        // Fetch user's cart from server
        Promise.all([fetchWishlist(), fetchCart()]).catch(console.error);
        
        return true;
      }
      return false;
    } catch (error) {
      console.error('Login error:', error);
      return false;
    }
  };

  // Logout function
  const logout = () => {
    clearAuth();
    setUser(null);
    setCart([]);
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <Header user={user} logout={logout} cartCount={cart.length} />
        <main className="container mx-auto px-4 py-4 sm:py-8">
          <Routes>
            <Route path="/" element={<HomePage products={products} loading={loading} />} />
            <Route path="/products" element={<ProductListPage products={products} loading={loading} />} />
            <Route path="/product/:id" element={<Suspense fallback={<LoadingSpinner />}><ProductDetailPage products={products} addToCart={addToCart} wishlistItems={wishlistItems} setWishlistItems={setWishlistItems} setNotification={setNotification} /></Suspense>} />
            <Route path="/cart" element={<CartPage cart={cart} removeFromCart={removeFromCart} updateCartQuantity={updateCartQuantity} addToCart={addToCart} user={user} setNotification={setNotification} />} />
            <Route path="/login" element={<LoginPage login={login} user={user} />} />

            <Route path="/orders" element={<Suspense fallback={<LoadingSpinner />}><OrderStatusPage user={user} /></Suspense>} />
            <Route path="/wishlist" element={<Suspense fallback={<LoadingSpinner />}><WishlistPage user={user} wishlistProducts={wishlistProducts} setWishlistProducts={setWishlistProducts} setWishlistItems={setWishlistItems} addToCart={addToCart} setNotification={setNotification} /></Suspense>} />
            <Route path="/profile" element={<Suspense fallback={<LoadingSpinner />}><ProfilePage user={user} setUser={setUser} /></Suspense>} />
            <Route path="/track/:orderId" element={<Suspense fallback={<LoadingSpinner />}><TrackOrderPage user={user} /></Suspense>} />
            <Route path="/checkout" element={<Suspense fallback={<LoadingSpinner />}><CheckoutPage user={user} /></Suspense>} />
            <Route path="/admin" element={<Suspense fallback={<LoadingSpinner />}><AdminPanel user={user} /></Suspense>} />
            <Route path="/support" element={<CustomerServicePage />} />
          </Routes>
        </main>
        <Footer />
        
        {/* Notification */}
        {notification && (
          <div className={`fixed top-4 right-4 text-white p-4 rounded-lg shadow-lg z-50 flex items-center space-x-3 ${
            notification.type === 'wishlist' ? 'bg-pink-500' : 'bg-green-500'
          }`}>
            <div>
              <p className="font-semibold">{notification.message}</p>
              <p className="text-sm opacity-90">{notification.product}</p>
            </div>
            <Link 
              to={notification.type === 'wishlist' ? '/wishlist' : '/cart'}
              className={`bg-white px-3 py-1 rounded text-sm font-medium hover:bg-gray-100 ${
                notification.type === 'wishlist' ? 'text-pink-500' : 'text-green-500'
              }`}
              onClick={() => setNotification(null)}
            >
              {notification.type === 'wishlist' ? 'Go to Wishlist' : 'Go to Cart'}
            </Link>
          </div>
        )}
      </div>
    </Router>
  );
}

// Header Component
const Header = React.memo(function Header({ user, logout, cartCount }) {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <header className="bg-white border-b border-gray-200 shadow-sm sticky top-0 z-50">
      <div className="container mx-auto px-4">
        <div className="flex justify-between items-center py-4">
          {/* Logo */}
          <Link to="/" className="flex items-center hover:opacity-80 transition-opacity">
            <img src="https://storage.googleapis.com/samriddhi-blog-images-123/Samriddhishop%20Logo%20Design.png" alt="SamriddhiShop" className="h-10" />
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden lg:flex items-center space-x-8">
            <Link to="/" className="text-gray-700 hover:text-blue-600 transition-colors font-medium">{t('Home')}</Link>
            <Link to="/products" className="text-gray-700 hover:text-blue-600 transition-colors font-medium">{t('Products')}</Link>
            <Link to="/cart" className="text-gray-700 hover:text-blue-600 transition-colors font-medium relative">
              <span className="flex items-center space-x-1">
                <span>🛒</span>
                <span>{t('Cart')}</span>
                {cartCount > 0 && (
                  <span className="bg-blue-600 text-white text-xs rounded-full px-2 py-1 ml-1">
                    {cartCount}
                  </span>
                )}
              </span>
            </Link>
            {user && <Link to="/orders" className="text-gray-700 hover:text-blue-600 transition-colors font-medium">My Orders</Link>}
            {user && <Link to="/wishlist" className="text-gray-700 hover:text-blue-600 transition-colors font-medium">Wishlist</Link>}
            {user && <Link to="/profile" className="text-gray-700 hover:text-blue-600 transition-colors font-medium">Profile</Link>}
            {user?.email === 'admin@samriddhishop.com' && (
              <Link to="/admin" className="bg-gray-900 hover:bg-gray-800 text-white px-3 py-2 rounded-lg font-medium transition-colors">
                Admin
              </Link>
            )}
            {user ? (
              <div className="flex items-center space-x-3">
                <span className="text-gray-600 text-sm">Hi, {user.name}</span>
                <button 
                  onClick={logout} 
                  className="bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-lg font-medium transition-colors border"
                >
                  {t('Logout')}
                </button>
              </div>
            ) : (
              <Link to="/login" className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors">
                {t('Login')}
              </Link>
            )}
          </nav>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="lg:hidden p-2 rounded-lg hover:bg-gray-100 transition-colors text-gray-700"
            aria-label={isMenuOpen ? 'Close menu' : 'Open menu'}
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {isMenuOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="lg:hidden pb-4 border-t border-gray-200 mt-4 bg-gray-50">
            <nav className="flex flex-col space-y-1 pt-4">
              <Link 
                to="/" 
                className="text-gray-700 hover:text-blue-600 hover:bg-white transition-colors font-medium py-3 px-4 rounded-lg mx-2"
                onClick={() => setIsMenuOpen(false)}
              >
                Home
              </Link>
              <Link 
                to="/products" 
                className="text-gray-700 hover:text-blue-600 hover:bg-white transition-colors font-medium py-3 px-4 rounded-lg mx-2"
                onClick={() => setIsMenuOpen(false)}
              >
                Products
              </Link>
              <Link 
                to="/cart" 
                className="text-gray-700 hover:text-blue-600 hover:bg-white transition-colors font-medium py-3 px-4 rounded-lg mx-2 flex items-center justify-between"
                onClick={() => setIsMenuOpen(false)}
              >
                <span>🛒 Cart</span>
                {cartCount > 0 && (
                  <span className="bg-blue-600 text-white text-xs rounded-full px-2 py-1">
                    {cartCount}
                  </span>
                )}
              </Link>
              {user && (
                <Link 
                  to="/orders" 
                  className="text-gray-700 hover:text-blue-600 hover:bg-white transition-colors font-medium py-3 px-4 rounded-lg mx-2"
                  onClick={() => setIsMenuOpen(false)}
                >
                  My Orders
                </Link>
              )}
              {user && (
                <Link 
                  to="/wishlist" 
                  className="text-gray-700 hover:text-blue-600 hover:bg-white transition-colors font-medium py-3 px-4 rounded-lg mx-2"
                  onClick={() => setIsMenuOpen(false)}
                >
                  Wishlist
                </Link>
              )}
              {user && (
                <Link 
                  to="/profile" 
                  className="text-gray-700 hover:text-blue-600 hover:bg-white transition-colors font-medium py-3 px-4 rounded-lg mx-2"
                  onClick={() => setIsMenuOpen(false)}
                >
                  Profile
                </Link>
              )}
              {user?.email === 'admin@samriddhishop.com' && (
                <Link 
                  to="/admin" 
                  className="bg-gray-900 hover:bg-gray-800 text-white px-4 py-3 rounded-lg font-medium transition-colors mx-2"
                  onClick={() => setIsMenuOpen(false)}
                >
                  Admin Panel
                </Link>
              )}
              {user ? (
                <div className="pt-3 mt-3 border-t border-gray-300 mx-2">
                  <p className="text-gray-600 text-sm mb-3 px-2">Hi, {user.name}</p>
                  <button 
                    onClick={() => {
                      logout();
                      setIsMenuOpen(false);
                    }} 
                    className="bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-3 rounded-lg font-medium transition-colors w-full border"
                  >
                    Logout
                  </button>
                </div>
              ) : (
                <Link 
                  to="/login" 
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-3 rounded-lg font-medium transition-colors mx-2 text-center"
                  onClick={() => setIsMenuOpen(false)}
                >
                  Login
                </Link>
              )}
            </nav>
          </div>
        )}
      </div>
    </header>
  );
});

// Home Page Component
function HomePage({ products, loading }) {
  const [banner, setBanner] = useState({
    title: 'Welcome to SamriddhiShop',
    subtitle: 'Discover amazing products at great prices',
    buttonText: 'Shop Now',
    backgroundImage: ''
  });

  useEffect(() => {
    fetchBanner();
  }, []);

  const fetchBanner = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/banner`);
      if (response.ok) {
        const data = await response.json();
        setBanner(data);
      }
    } catch (error) {
      console.error('Error fetching banner:', error);
    }
  };

  // Group products by category
  const productsByCategory = products.reduce((acc, product) => {
    const category = product.category;
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(product);
    return acc;
  }, {});

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      {/* Hero Banner */}
      <div className="relative text-white p-12 rounded-lg mb-8 bg-gradient-to-r from-blue-500 to-purple-600 overflow-hidden">
        {banner.backgroundImage && (
          <>
            <img
              src={banner.backgroundImage}
              alt={banner.title || 'Promotional banner'}
              className="absolute inset-0 w-full h-full object-cover"
              fetchpriority="high"
            />
            <div className="absolute inset-0 bg-black bg-opacity-40"></div>
          </>
        )}
        <div className="relative z-10">
          <h1 className="text-4xl font-bold mb-4">{banner.title}</h1>
          <p className="text-xl mb-6">{banner.subtitle}</p>
          <Link to="/products" className="bg-white text-blue-600 px-6 py-3 rounded-lg font-semibold hover:bg-gray-100 transition-colors">
            {banner.buttonText}
          </Link>
        </div>
      </div>
      
      {/* Promotional Banner */}
      <div className="bg-yellow-400 text-black p-4 rounded-lg mb-8 text-center">
        <h2 className="text-2xl font-bold mb-2">🎉 Special Offer!</h2>
        <p className="text-lg">Get 20% off on your first order. Use code: WELCOME20</p>
      </div>
      
      {/* Products by Category */}
      {Object.entries(productsByCategory).map(([category, categoryProducts]) => (
        <section key={category} className="mb-12">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-3xl font-bold capitalize">{category}</h2>
            <Link 
              to={`/products?category=${encodeURIComponent(category)}`}
              className="text-blue-600 hover:text-blue-800 font-medium"
            >
              View All →
            </Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {categoryProducts.slice(0, 4).map(product => (
              <ProductCard key={product._id} product={product} />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

// Product List Page Component
function ProductListPage({ products, loading }) {
  const navigate = useNavigate();
  const [filteredProducts, setFilteredProducts] = useState([]);
  const [filters, setFilters] = useState({
    category: '',
    minPrice: '',
    maxPrice: '',
    minRating: '',
    sortBy: 'name'
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    applyFilters();
  }, [products, filters, searchTerm]);

  const applyFilters = () => {
    let filtered = [...products];

    // Search by name
    if (searchTerm) {
      filtered = filtered.filter(product => 
        product.name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Filter by category
    if (filters.category) {
      filtered = filtered.filter(product => product.category === filters.category);
    }

    // Filter by price range
    if (filters.minPrice) {
      const minPrice = parseFloat(filters.minPrice);
      if (!isNaN(minPrice)) {
        filtered = filtered.filter(product => product.price >= minPrice);
      }
    }
    if (filters.maxPrice) {
      const maxPrice = parseFloat(filters.maxPrice);
      if (!isNaN(maxPrice)) {
        filtered = filtered.filter(product => product.price <= maxPrice);
      }
    }

    // Filter by rating
    if (filters.minRating) {
      const minRating = parseFloat(filters.minRating);
      if (!isNaN(minRating)) {
        filtered = filtered.filter(product => (product.averageRating || 0) >= minRating);
      }
    }

    // Sort products
    filtered.sort((a, b) => {
      switch (filters.sortBy) {
        case 'price-low':
          return a.price - b.price;
        case 'price-high':
          return b.price - a.price;
        case 'rating':
          return (b.averageRating || 0) - (a.averageRating || 0);
        case 'name':
        default:
          return a.name.localeCompare(b.name);
      }
    });

    setFilteredProducts(filtered);
  };

  const categories = [...new Set(products.map(p => p.category))];

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      {/* Back Button */}
      <button 
        onClick={() => navigate('/')}
        className="mb-6 flex items-center space-x-2 text-blue-600 hover:text-blue-800 transition-colors"
      >
        <span>←</span>
        <span>Back to Home</span>
      </button>

      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold">All Products</h1>
        
        {/* Mobile Filter Button */}
        <button
          onClick={() => setShowFilters(true)}
          className="md:hidden bg-white hover:bg-gray-50 text-gray-800 hover:text-gray-900 px-4 py-2 rounded-lg border border-gray-300 hover:border-gray-400 flex items-center space-x-2 shadow-sm hover:shadow-md transition-all duration-200 font-medium"
        >
          <span>🔍</span>
          <span>Filters</span>
        </button>
      </div>
      
      {/* Desktop Filters */}
      <div className="hidden md:block bg-white p-6 rounded-lg shadow mb-8">
        <h3 className="text-lg font-semibold mb-4">Filters</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
          {/* Search */}
          <input
            type="text"
            placeholder="Search products..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          
          {/* Category */}
          <select
            value={filters.category}
            onChange={(e) => setFilters({...filters, category: e.target.value})}
            className="px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Categories</option>
            {categories.map(category => (
              <option key={category} value={category}>{category}</option>
            ))}
          </select>
          
          {/* Min Price */}
          <input
            type="number"
            placeholder="Min Price"
            value={filters.minPrice}
            onChange={(e) => setFilters({...filters, minPrice: e.target.value})}
            className="px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          
          {/* Max Price */}
          <input
            type="number"
            placeholder="Max Price"
            value={filters.maxPrice}
            onChange={(e) => setFilters({...filters, maxPrice: e.target.value})}
            className="px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          
          {/* Min Rating */}
          <select
            value={filters.minRating}
            onChange={(e) => setFilters({...filters, minRating: e.target.value})}
            className="px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">Any Rating</option>
            <option value="4">4+ Stars</option>
            <option value="3">3+ Stars</option>
            <option value="2">2+ Stars</option>
            <option value="1">1+ Stars</option>
          </select>
          
          {/* Sort By */}
          <select
            value={filters.sortBy}
            onChange={(e) => setFilters({...filters, sortBy: e.target.value})}
            className="px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="name">Sort by Name</option>
            <option value="price-low">Price: Low to High</option>
            <option value="price-high">Price: High to Low</option>
            <option value="rating">Highest Rated</option>
          </select>
        </div>
        
        {/* Clear Filters */}
        <button
          onClick={() => {
            setFilters({ category: '', minPrice: '', maxPrice: '', minRating: '', sortBy: 'name' });
            setSearchTerm('');
          }}
          className="mt-4 bg-gray-500 text-white px-4 py-2 rounded-lg hover:bg-gray-600 transition-colors"
        >
          Clear Filters
        </button>
      </div>
      
      {/* Mobile Filter Sidebar */}
      {showFilters && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 bg-black bg-opacity-50" onClick={() => setShowFilters(false)}></div>
          <div className="absolute right-0 top-0 h-full w-80 bg-white shadow-lg overflow-y-auto">
            <div className="p-6">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-lg font-semibold">Filters</h3>
                <button
                  onClick={() => setShowFilters(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                {/* Search */}
                <div>
                  <label className="block text-sm font-medium mb-2">Search</label>
                  <input
                    type="text"
                    placeholder="Search products..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                {/* Category */}
                <div>
                  <label className="block text-sm font-medium mb-2">Category</label>
                  <select
                    value={filters.category}
                    onChange={(e) => setFilters({...filters, category: e.target.value})}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="">All Categories</option>
                    {categories.map(category => (
                      <option key={category} value={category}>{category}</option>
                    ))}
                  </select>
                </div>
                
                {/* Price Range */}
                <div>
                  <label className="block text-sm font-medium mb-2">Price Range</label>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="number"
                      placeholder="Min Price"
                      value={filters.minPrice}
                      onChange={(e) => setFilters({...filters, minPrice: e.target.value})}
                      className="px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <input
                      type="number"
                      placeholder="Max Price"
                      value={filters.maxPrice}
                      onChange={(e) => setFilters({...filters, maxPrice: e.target.value})}
                      className="px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>
                
                {/* Rating */}
                <div>
                  <label className="block text-sm font-medium mb-2">Minimum Rating</label>
                  <select
                    value={filters.minRating}
                    onChange={(e) => setFilters({...filters, minRating: e.target.value})}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="">Any Rating</option>
                    <option value="4">4+ Stars</option>
                    <option value="3">3+ Stars</option>
                    <option value="2">2+ Stars</option>
                    <option value="1">1+ Stars</option>
                  </select>
                </div>
                
                {/* Sort By */}
                <div>
                  <label className="block text-sm font-medium mb-2">Sort By</label>
                  <select
                    value={filters.sortBy}
                    onChange={(e) => setFilters({...filters, sortBy: e.target.value})}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="name">Sort by Name</option>
                    <option value="price-low">Price: Low to High</option>
                    <option value="price-high">Price: High to Low</option>
                    <option value="rating">Highest Rated</option>
                  </select>
                </div>
              </div>
              
              {/* Action Buttons */}
              <div className="mt-6 space-y-3">
                <button
                  onClick={() => {
                    setFilters({ category: '', minPrice: '', maxPrice: '', minRating: '', sortBy: 'name' });
                    setSearchTerm('');
                  }}
                  className="w-full bg-gray-500 text-white px-4 py-2 rounded-lg hover:bg-gray-600 transition-colors"
                >
                  Clear Filters
                </button>
                <button
                  onClick={() => setShowFilters(false)}
                  className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Apply Filters
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Results Count */}
      <p className="text-gray-600 mb-4">
        Showing {filteredProducts.length} of {products.length} products
      </p>
      
      {/* Products Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {filteredProducts.slice(0, 12).map(product => (
          <ProductCard key={product._id} product={product} />
        ))}
      </div>
      {filteredProducts.length > 12 && (
        <div className="text-center mt-8">
          <p className="text-gray-600">Showing 12 of {filteredProducts.length} products</p>
        </div>
      )}
      
      {filteredProducts.length === 0 && (
        <div className="text-center py-12">
          <p className="text-gray-600 text-lg">No products found matching your criteria.</p>
        </div>
      )}
    </div>
  );
}

// Product Detail Page Component
function ProductDetailPageComponent({ products, addToCart, wishlistItems, setWishlistItems, setNotification }) {
  const { id } = useParams();
  const navigate = useNavigate();
  const [selectedImage, setSelectedImage] = useState(0);
  const [quantity, setQuantity] = useState(1);
  const [selectedVariant, setSelectedVariant] = useState(null);
  const [canReview, setCanReview] = useState(false);
  const [rating, setRating] = useState(5);
  const [review, setReview] = useState('');
  const [showReviewForm, setShowReviewForm] = useState(false);
  const product = products.find(p => p._id === id);
  
  useEffect(() => {
    const token = localStorage.getItem('token');
    setCanReview(!!token);
  }, [id]);
  
  const checkReviewEligibility = async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      setCanReview(false);
      return;
    }
    
    try {
      const response = await fetch(`${API_BASE}/api/orders`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (!response.ok) {
        setCanReview(false);
        return;
      }
      
      const orders = await response.json();
      
      const hasPurchased = orders.some(order => 
        order.items.some(item => item.productId === id)
      );
      
      setCanReview(hasPurchased);
    } catch (error) {
      console.error('Error checking review eligibility:', error);
      setCanReview(true);
    }
  };
  
  const submitReview = async () => {
    const token = getToken();
    if (!token) {
      alert('Please login to submit a review');
      return;
    }
    
    try {
      const response = await makeSecureRequest(`${API_BASE}/products/${id}/rating`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ rating, review })
      });
      
      if (response.ok) {
        alert('Review submitted successfully!');
        setShowReviewForm(false);
        setReview('');
        window.location.reload();
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to submit review');
      }
    } catch (error) {
      alert('Failed to submit review');
    }
  };

  const handleBuyNow = () => {
    if (product.variants && product.variants.length > 0 && !selectedVariant) {
      alert('Please select size and color');
      return;
    }
    const buyNowItem = { ...product, quantity, selectedVariant };
    navigate('/checkout', { state: { items: [buyNowItem], total: product.price * quantity, buyNow: true } });
  };

  const handleAddToCart = () => {
    if (product.variants && product.variants.length > 0 && !selectedVariant) {
      alert('Please select size and color');
      return;
    }
    const productWithVariant = { ...product, selectedVariant };
    for (let i = 0; i < quantity; i++) {
      addToCart(productWithVariant);
    }
  };

  if (!product) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-6xl mb-4">🔍</div>
          <h2 className="text-2xl font-bold text-gray-800 mb-2">Product Not Found</h2>
          <p className="text-gray-600 mb-6">The product you're looking for doesn't exist.</p>
          <button 
            onClick={() => navigate('/products')}
            className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Browse Products
          </button>
        </div>
      </div>
    );
  }

  const images = [product.imageUrl, ...(product.images || [])].filter(Boolean);

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4">
        {/* Breadcrumb */}
        <nav className="mb-8">
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <Link to="/" className="hover:text-blue-600">Home</Link>
            <span>/</span>
            <Link to="/products" className="hover:text-blue-600">Products</Link>
            <span>/</span>
            <span className="text-gray-800">{product.name}</span>
          </div>
        </nav>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
          {/* Product Images */}
          <div className="lg:sticky lg:top-8 lg:h-fit space-y-4">
            <div className="aspect-square bg-white rounded-2xl shadow-lg overflow-hidden relative">
              <img 
                src={images[selectedImage]} 
                alt={product.name}
                className="w-full h-full object-cover"
              />
              {product.originalPrice && product.discountPercentage && product.discountPercentage > 0 && (
                <div className="absolute top-4 left-4 bg-red-500 text-white px-3 py-1 rounded-full text-sm font-bold shadow-lg">
                  {product.discountPercentage}% OFF
                </div>
              )}
              
              {/* Wishlist Heart Button */}
              <button
                onClick={async () => {
                  const token = getToken();
                  if (!token) {
                    alert('Please login to add to wishlist');
                    return;
                  }
                  
                  const isInWishlist = wishlistItems && wishlistItems.includes(product._id);
                  
                  try {
                    const response = await fetch(`${API_BASE}/api/wishlist/${product._id}`, {
                      method: isInWishlist ? 'DELETE' : 'POST',
                      headers: { 'Authorization': `Bearer ${token}` }
                    });
                    const data = await response.json();
                    if (response.ok) {
                      if (isInWishlist) {
                        setWishlistItems && setWishlistItems(prev => prev.filter(id => id !== product._id));
                        setNotification && setNotification({ message: 'Removed from wishlist', product: product.name, type: 'wishlist' });
                      } else {
                        setWishlistItems && setWishlistItems(prev => [...prev, product._id]);
                        setNotification && setNotification({ message: 'Added to wishlist', product: product.name, type: 'wishlist' });
                      }
                      setTimeout(() => setNotification && setNotification(null), 3000);
                    } else {
                      alert(data.error || `Failed to ${isInWishlist ? 'remove from' : 'add to'} wishlist`);
                    }
                  } catch (error) {
                    alert(`Failed to ${isInWishlist ? 'remove from' : 'add to'} wishlist`);
                  }
                }
                className={`absolute bottom-4 right-4 w-12 h-12 rounded-full shadow-lg transition-all duration-200 flex items-center justify-center ${
                  wishlistItems && wishlistItems.includes(product._id)
                    ? 'bg-red-500 text-white'
                    : 'bg-white text-gray-600 hover:bg-red-50 hover:text-red-500'
                }`}
              >
                <svg className="w-6 h-6" fill={wishlistItems && wishlistItems.includes(product._id) ? 'currentColor' : 'none'} stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" />
                </svg>
              </button>
              
              {/* Share Button */}
              <button
                onClick={() => {
                  if (navigator.share) {
                    navigator.share({
                      title: product.name,
                      text: product.description,
                      url: window.location.href
                    });
                  } else {
                    navigator.clipboard.writeText(window.location.href);
                    alert('Product link copied to clipboard!');
                  }
                }}
                className="absolute bottom-4 left-4 w-12 h-12 bg-white text-gray-600 rounded-full shadow-lg hover:bg-blue-50 hover:text-blue-500 transition-all duration-200 flex items-center justify-center"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.367 2.684 3 3 0 00-5.367-2.684z" />
                </svg>
              </button>
            </div>
            <div className="flex space-x-3">
              {images.map((img, index) => (
                <button
                  key={index}
                  onClick={() => setSelectedImage(index)}
                  className={`w-20 h-20 rounded-lg overflow-hidden border-2 transition-colors ${
                    selectedImage === index ? 'border-blue-500' : 'border-gray-200'
                  }`}
                >
                  <img src={img} alt={`View ${index + 1}`} className="w-full h-full object-cover" />
                </button>
              ))}
            </div>
          </div>

          {/* Product Info */}
          <div className="space-y-6">
            <div>
              <div className="flex items-center space-x-2 mb-2">
                <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">
                  {product.category}
                </span>
                <div className="flex items-center text-yellow-400">
                  {'★'.repeat(Math.floor(product.averageRating || 0))}{'☆'.repeat(5 - Math.floor(product.averageRating || 0))}
                  <span className="text-gray-600 text-sm ml-2">({product.averageRating || 0}) {product.totalRatings || 0} reviews</span>
                </div>
              </div>
              <h1 className="text-3xl lg:text-4xl font-bold text-gray-900 mb-4">{product.name}</h1>
              <p className="text-gray-600 text-lg leading-relaxed">{product.description}</p>
            </div>

            {/* Price */}
            <div className="bg-white p-6 rounded-xl shadow-sm border">
              <div className="flex items-baseline space-x-3">
                <span className="text-3xl font-bold text-gray-900">₹{product.price.toLocaleString()}</span>
                {product.originalPrice && product.discountPercentage && product.discountPercentage > 0 && (
                  <>
                    <span className="text-lg text-gray-500 line-through">₹{product.originalPrice.toLocaleString()}</span>
                    <span className="bg-red-100 text-red-800 text-sm px-2 py-1 rounded">{product.discountPercentage}% OFF</span>
                  </>
                )}
              </div>
            </div>

            {/* Variant Selector */}
            {product.variants && product.variants.length > 0 && (
              <div className="bg-white p-6 rounded-xl shadow-sm border">
                <h3 className="font-semibold text-gray-900 mb-3">Select Size & Color</h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {product.variants.map((variant, index) => (
                    <button
                      key={index}
                      onClick={() => setSelectedVariant(variant)}
                      className={`p-3 border rounded-lg text-sm font-medium transition-colors ${
                        selectedVariant === variant
                          ? 'border-blue-500 bg-blue-50 text-blue-700'
                          : 'border-gray-300 hover:border-gray-400'
                      } ${variant.stock <= 0 ? 'opacity-50 cursor-not-allowed' : ''}`}
                      disabled={variant.stock <= 0}
                    >
                      <div>{variant.size} - {variant.color}</div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Quantity Selector */}
            <div className="bg-white p-6 rounded-xl shadow-sm border">
              <h3 className="font-semibold text-gray-900 mb-3">{t('Quantity')}</h3>
              <div className="flex items-center space-x-4">
                <div className="flex items-center border border-gray-300 rounded-lg">
                  <button 
                    onClick={() => setQuantity(Math.max(1, quantity - 1))}
                    className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded-l-lg"
                  >
                    -
                  </button>
                  <span className="px-4 py-2 border-x border-gray-300 min-w-[60px] text-center">{quantity}</span>
                  <button 
                    onClick={() => setQuantity(quantity + 1)}
                    className="px-4 py-2 text-gray-600 hover:bg-gray-100 rounded-r-lg"
                  >
                    +
                  </button>
                </div>

              </div>
            </div>

            {/* Action Buttons */}
            <div className="space-y-4">
              <button 
                onClick={handleBuyNow}
                className="w-full bg-orange-500 text-white py-4 px-8 rounded-xl text-lg font-semibold hover:bg-orange-600 transition-colors shadow-lg"
              >
                🛒 Buy Now - ₹{(product.price * quantity).toLocaleString()}
              </button>
              <button 
                onClick={handleAddToCart}
                className="w-full bg-blue-600 text-white py-4 px-8 rounded-xl text-lg font-semibold hover:bg-blue-700 transition-colors border-2 border-blue-600"
              >
                {t('Add to Cart')}
              </button>

            </div>

            {/* Product Highlights */}
            {product.showHighlights && product.highlights && product.highlights.length > 0 && (
              <div className="bg-blue-50 p-6 rounded-xl">
                <h3 className="font-semibold text-blue-900 mb-4">✨ Product Highlights</h3>
                <div className="space-y-3">
                  {product.highlights.map((highlight, index) => (
                    <div key={index} className="flex items-center space-x-3">
                      <span className="text-blue-500">✓</span>
                      <span className="text-blue-800">{highlight}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Product Specifications */}
            {product.showSpecifications && product.specifications && product.specifications.length > 0 && (
              <div className="bg-gray-50 p-6 rounded-xl">
                <h3 className="font-semibold text-gray-900 mb-4">📋 Specifications</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {product.specifications.map((spec, index) => (
                    <div key={index} className="flex justify-between py-2 border-b border-gray-200 last:border-b-0">
                      <span className="font-medium text-gray-700">{spec.key}:</span>
                      <span className="text-gray-600">{spec.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Warranty Information */}
            {product.showWarranty && product.warranty && (
              <div className="bg-green-50 p-6 rounded-xl">
                <h3 className="font-semibold text-green-900 mb-4">🛡️ Warranty</h3>
                <p className="text-green-800 whitespace-pre-line">{product.warranty}</p>
              </div>
            )}

            
            {/* Review Section */}
            {canReview && (
              <div className="bg-blue-50 p-6 rounded-xl border border-blue-200">
                <h3 className="font-semibold text-blue-800 mb-3">⭐ Rate this Product</h3>
                <p className="text-blue-700 text-sm mb-4">Share your thoughts about this product.</p>
                
                {!showReviewForm ? (
                  <button
                    onClick={() => setShowReviewForm(true)}
                    className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    Write a Review
                  </button>
                ) : (
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-blue-800 mb-2">Rating</label>
                      <div className="flex space-x-1">
                        {[1, 2, 3, 4, 5].map(star => (
                          <button
                            key={star}
                            onClick={() => setRating(star)}
                            className={`text-2xl ${star <= rating ? 'text-yellow-400' : 'text-gray-300'}`}
                          >
                            ★
                          </button>
                        ))}
                      </div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-blue-800 mb-2">Review</label>
                      <textarea
                        value={review}
                        onChange={(e) => setReview(e.target.value)}
                        className="w-full px-3 py-2 border border-blue-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        rows="3"
                        placeholder="Share your experience with this product..."
                      />
                    </div>
                    
                    <div className="flex space-x-3">
                      <button
                        onClick={submitReview}
                        className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                      >
                        Submit Review
                      </button>
                      <button
                        onClick={() => setShowReviewForm(false)}
                        className="bg-gray-500 text-white px-4 py-2 rounded-lg hover:bg-gray-600 transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
            
            {/* Customer Reviews */}
            {product.ratings && product.ratings.length > 0 && (
              <div className="bg-white p-6 rounded-xl shadow-sm border">
                <h3 className="font-semibold text-gray-900 mb-4">Customer Reviews</h3>
                <div className="space-y-4">
                  {product.ratings.map((rating, index) => (
                    <div key={index} className="border-b border-gray-100 pb-4 last:border-b-0">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <span className="font-medium text-gray-900">{rating.userId?.name || 'Anonymous'}</span>
                          <div className="flex text-yellow-400">
                            {'★'.repeat(rating.rating)}{'☆'.repeat(5 - rating.rating)}
                          </div>
                        </div>
                        <span className="text-sm text-gray-500">
                          {new Date(rating.createdAt).toLocaleDateString('en-IN')}
                        </span>
                      </div>
                      {rating.review && (
                        <p className="text-gray-700">{rating.review}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Checkout Page Component
function CheckoutPageComponent({ user }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [addresses, setAddresses] = useState([]);
  const [selectedAddress, setSelectedAddress] = useState('');
  const [newAddress, setNewAddress] = useState({ street: '', city: '', state: '', zipCode: '', country: 'India' });
  const [paymentMethod, setPaymentMethod] = useState('cod');
  const [loading, setLoading] = useState(false);
  const [couponCode, setCouponCode] = useState('');
  const [discount, setDiscount] = useState(0);
  const [couponId, setCouponId] = useState(null);
  const [shippingCost, setShippingCost] = useState(0);
  
  const { items = [], total = 0, buyNow = false } = location.state || {};
  
  const subtotal = total;
  const tax = Math.round(subtotal * 0.18);
  const finalTotal = subtotal + tax + shippingCost - discount;

  const applyCoupon = async () => {
    if (!couponCode.trim()) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/apply-coupon`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ code: couponCode, total })
      });
      
      const data = await response.json();
      if (response.ok) {
        setDiscount(data.discount);
        setCouponId(data.couponId);
        alert(`Coupon applied! ₹${data.discount} discount`);
      } else {
        alert(data.error || 'Invalid coupon code');
      }
    } catch (error) {
      alert('Failed to apply coupon');
    }
  };

  useEffect(() => {
    if (!user) {
      navigate('/login', { state: { from: location } });
      return;
    }
    if (!items || items.length === 0) {
      navigate('/cart');
      return;
    }
    fetchAddresses();
    fetchShippingCost();
  }, [user, items, navigate]);

  const fetchShippingCost = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/shipping-cost`);
      const data = await response.json();
      setShippingCost(data.cost || 0);
    } catch (error) {
      console.error('Error fetching shipping cost:', error);
    }
  };

  const fetchAddresses = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/profile`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setAddresses(data.addresses || []);
    } catch (error) {
      console.error('Error fetching addresses:', error);
    }
  };

  const processOrder = async () => {
    let shippingAddress;
    
    if (selectedAddress) {
      shippingAddress = addresses.find(addr => addr._id === selectedAddress);
    } else if (newAddress.street && newAddress.city) {
      shippingAddress = newAddress;
    } else {
      alert('Please select or enter a shipping address');
      return;
    }

    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/checkout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ items, total, shippingAddress, paymentMethod, couponCode, couponId, discount, shippingCost, tax: tax })
      });

      if (response.ok) {
        const data = await response.json();
        alert('Order placed successfully!');
        navigate(`/track/${data.orderId}`);
      } else {
        const error = await response.json();
        alert(error.error || 'Checkout failed');
      }
    } catch (error) {
      console.error('Checkout error:', error);
      alert('Checkout failed. Please try again.');
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-6xl mx-auto px-4">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Checkout</h1>
          <p className="text-gray-600 mt-2">{buyNow ? 'Complete your purchase' : 'Review your order and complete payment'}</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Checkout Form */}
          <div className="lg:col-span-2 space-y-6">
            {/* Delivery Address */}
            <div className="bg-white p-6 rounded-xl shadow-sm border">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">🏠 Delivery Address</h2>
              
              {addresses.length > 0 && (
                <div className="space-y-3 mb-6">
                  <h3 className="font-medium text-gray-700">Saved Addresses</h3>
                  {addresses.map(address => (
                    <label key={address._id} className="flex items-start space-x-3 p-4 border border-gray-200 rounded-lg hover:border-blue-300 cursor-pointer">
                      <input
                        type="radio"
                        name="address"
                        value={address._id}
                        onChange={(e) => setSelectedAddress(e.target.value)}
                        className="mt-1 text-blue-500"
                      />
                      <div className="flex-1">
                        <p className="font-medium text-gray-900">{address.street}</p>
                        <p className="text-gray-600">{address.city}, {address.state} - {address.zipCode}</p>
                        <p className="text-gray-500 text-sm">{address.country}</p>
                      </div>
                    </label>
                  ))}
                </div>
              )}
              
              <div className="border-t pt-6">
                <label className="flex items-center space-x-3 mb-4">
                  <input
                    type="radio"
                    name="address"
                    onChange={() => setSelectedAddress('')}
                    className="text-blue-500"
                  />
                  <span className="font-medium text-gray-900">Add New Address</span>
                </label>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <input
                    type="text"
                    placeholder="Street Address *"
                    value={newAddress.street}
                    onChange={(e) => setNewAddress({...newAddress, street: e.target.value})}
                    className="px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <input
                    type="text"
                    placeholder="City *"
                    value={newAddress.city}
                    onChange={(e) => setNewAddress({...newAddress, city: e.target.value})}
                    className="px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <input
                    type="text"
                    placeholder="State"
                    value={newAddress.state}
                    onChange={(e) => setNewAddress({...newAddress, state: e.target.value})}
                    className="px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <input
                    type="text"
                    placeholder="ZIP Code"
                    value={newAddress.zipCode}
                    onChange={(e) => setNewAddress({...newAddress, zipCode: e.target.value})}
                    className="px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>
            </div>

            {/* Payment Method */}
            <div className="bg-white p-6 rounded-xl shadow-sm border">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">💳 Payment Method</h2>
              <div className="space-y-3">
                <label className="flex items-center space-x-3 p-4 border border-gray-200 rounded-lg hover:border-blue-300 cursor-pointer">
                  <input
                    type="radio"
                    name="payment"
                    value="cod"
                    checked={paymentMethod === 'cod'}
                    onChange={(e) => setPaymentMethod(e.target.value)}
                    className="text-blue-500"
                  />
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">💵</span>
                    <div>
                      <p className="font-medium text-gray-900">Cash on Delivery</p>
                      <p className="text-gray-600 text-sm">Pay when you receive your order</p>
                    </div>
                  </div>
                </label>
                
                <label className="flex items-center space-x-3 p-4 border border-gray-200 rounded-lg hover:border-blue-300 cursor-pointer opacity-50">
                  <input type="radio" disabled className="text-blue-500" />
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">💳</span>
                    <div>
                      <p className="font-medium text-gray-900">Credit/Debit Card</p>
                      <p className="text-gray-600 text-sm">Coming soon</p>
                    </div>
                  </div>
                </label>
                
                <label className="flex items-center space-x-3 p-4 border border-gray-200 rounded-lg hover:border-blue-300 cursor-pointer opacity-50">
                  <input type="radio" disabled className="text-blue-500" />
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">📱</span>
                    <div>
                      <p className="font-medium text-gray-900">UPI Payment</p>
                      <p className="text-gray-600 text-sm">Coming soon</p>
                    </div>
                  </div>
                </label>
              </div>
            </div>
          </div>

          {/* Order Summary */}
          <div className="lg:col-span-1">
            <div className="bg-white p-6 rounded-xl shadow-sm border sticky top-8">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">📋 Order Summary</h2>
              
              <div className="space-y-4 mb-6">
                {items.map((item, index) => (
                  <div key={index} className="flex items-center space-x-3">
                    <img src={item.imageUrl} alt={item.name} className="w-16 h-16 object-cover rounded-lg" />
                    <div className="flex-1">
                      <h3 className="font-medium text-gray-900 text-sm">{item.name}</h3>
                      {item.selectedVariant && (
                        <p className="text-gray-500 text-xs">{item.selectedVariant.size} - {item.selectedVariant.color}</p>
                      )}
                      <p className="text-gray-600 text-sm">Qty: {item.quantity}</p>
                    </div>
                    <p className="font-semibold text-gray-900">₹{(item.price * item.quantity).toLocaleString()}</p>
                  </div>
                ))}
              </div>
              
              {/* Coupon Code */}
              <div className="border-t pt-4 mb-4">
                <div className="flex space-x-2">
                  <input
                    type="text"
                    placeholder="Enter coupon code"
                    value={couponCode}
                    onChange={(e) => setCouponCode(e.target.value.toUpperCase())}
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    onClick={applyCoupon}
                    className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    Apply
                  </button>
                </div>
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-gray-600">
                  <span>Subtotal</span>
                  <span>₹{subtotal.toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-gray-600">
                  <span>Shipping</span>
                  <span>{shippingCost > 0 ? `₹${shippingCost}` : 'Free'}</span>
                </div>
                <div className="flex justify-between text-gray-600">
                  <span>Tax (18%)</span>
                  <span>₹{tax.toLocaleString()}</span>
                </div>
                {discount > 0 && (
                  <div className="flex justify-between text-green-600">
                    <span>Discount ({couponCode})</span>
                    <span>-₹{discount.toLocaleString()}</span>
                  </div>
                )}
                <div className="border-t pt-2 flex justify-between text-lg font-bold text-gray-900">
                  <span>Total</span>
                  <span>₹{finalTotal.toLocaleString()}</span>
                </div>
              </div>
              
              <button
                onClick={processOrder}
                disabled={loading}
                className="w-full mt-6 bg-green-600 text-white py-4 px-6 rounded-xl text-lg font-semibold hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? '⏳ Processing...' : '🛒 Place Order'}
              </button>
              
              <div className="mt-4 text-center">
                <p className="text-gray-500 text-sm">🔒 Your payment information is secure</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Cart Item Card Component
function CartItemCard({ item, hasDiscount, updateCartQuantity, removeFromCart }) {
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const images = [item.imageUrl, ...(item.images || [])].filter(Boolean);
  
  useEffect(() => {
    if (images.length > 1) {
      const interval = setInterval(() => {
        setCurrentImageIndex(prev => (prev + 1) % images.length);
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [images.length]);
  
  return (
    <div className="bg-white rounded-lg shadow hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2 group">
      <Link to={`/product/${item._id}`}>
        <div className="relative overflow-hidden rounded-t-lg">
          <img 
            src={images[currentImageIndex]} 
            alt={item.name}
            className="w-full h-48 object-cover transition-all duration-300 group-hover:scale-105"
          />
          {hasDiscount && (
            <div className="absolute top-2 left-2 bg-red-500 text-white px-2 py-1 rounded text-xs font-bold">
              {item.discountPercentage}% OFF
            </div>
          )}
          {images.length > 1 && (
            <div className="absolute bottom-2 left-1/2 transform -translate-x-1/2 flex space-x-1">
              {images.map((_, index) => (
                <div
                  key={index}
                  className={`w-1.5 h-1.5 rounded-full ${
                    index === currentImageIndex ? 'bg-white' : 'bg-white bg-opacity-50'
                  }`}
                />
              ))}
            </div>
          )}
        </div>
      </Link>
      <div className="p-4">
        <Link to={`/product/${item._id}`}>
          <h3 className="font-semibold text-lg mb-2 group-hover:text-blue-600 transition-colors cursor-pointer">{item.name}</h3>
        </Link>
        {item.selectedVariant && (
          <p className="text-blue-600 text-sm mb-1">{item.selectedVariant.size} - {item.selectedVariant.color}</p>
        )}
        <p className="text-gray-600 text-sm mb-2">{item.description?.substring(0, 100)}...</p>
        
        <div className="flex items-center mb-2">
          <div className="flex text-yellow-400 text-sm">
            {'★'.repeat(Math.floor(item.averageRating || 0))}{'☆'.repeat(5 - Math.floor(item.averageRating || 0))}
          </div>
          <span className="text-gray-500 text-xs ml-1">({item.totalRatings || 0})</span>
        </div>
        
        <div className="flex items-center space-x-2 mb-3">
          <span className="text-xl font-bold text-green-600">₹{item.price.toLocaleString()}</span>
          {hasDiscount && (
            <>
              <span className="text-sm text-gray-500 line-through">₹{item.originalPrice.toLocaleString()}</span>
              <span className="bg-red-100 text-red-800 text-xs px-1 py-0.5 rounded">{item.discountPercentage}% OFF</span>
            </>
          )}
        </div>
        
        <div className="flex items-center justify-between">
          <div className="flex items-center border border-gray-300 rounded">
            <button 
              onClick={() => updateCartQuantity(item._id, item.quantity - 1)}
              className="px-3 py-1 hover:bg-gray-100"
            >
              -
            </button>
            <span className="px-3 py-1 border-x">{item.quantity}</span>
            <button 
              onClick={() => updateCartQuantity(item._id, item.quantity + 1)}
              className="px-3 py-1 hover:bg-gray-100"
            >
              +
            </button>
          </div>
          <button 
            onClick={() => removeFromCart(item._id)}
            className="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600 text-sm"
          >
            Remove
          </button>
        </div>
        
        <div className="mt-3 text-right">
          <span className="font-bold text-lg">₹{(item.price * item.quantity).toLocaleString()}</span>
        </div>
      </div>
    </div>
  );
}

// Shopping Cart Page Component
function CartPage({ cart, removeFromCart, updateCartQuantity, addToCart, user, setNotification }) {
  const navigate = useNavigate();
  const [products, setProducts] = useState([]);
  const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);

  useEffect(() => {
    fetchSuggestedProducts();
  }, []);

  const fetchSuggestedProducts = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/products`);
      const data = await response.json();
      setProducts(data.slice(0, 4));
    } catch (error) {
      console.error('Error fetching products:', error);
    }
  };

  const handleAddToCart = (product) => {
    addToCart(product);
  };

  const handleCheckout = () => {
    if (!user) {
      navigate('/login');
      return;
    }
    navigate('/checkout', { state: { items: cart, total, buyNow: false } });
  };

  if (cart.length === 0) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-gray-600 mb-4">{t('Your cart is empty')}</h2>
        <Link to="/products" className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
          {t('Continue Shopping')}
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mb-8">Shopping Cart</h1>
      
      {/* Cart Items */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        {cart.map(item => {
          const hasDiscount = item.originalPrice && item.discountPercentage && item.discountPercentage > 0;
          return (
            <CartItemCard 
              key={item._id} 
              item={item} 
              hasDiscount={hasDiscount}
              updateCartQuantity={updateCartQuantity}
              removeFromCart={removeFromCart}
            />
          );
        })}
      </div>

      
      {/* Checkout Section */}
      <div className="bg-white p-6 rounded-lg shadow mb-8">
        <div className="flex justify-between items-center mb-4">
          <span className="text-xl font-bold">Total: ₹{total.toLocaleString()}</span>
        </div>
        
        <button 
          onClick={handleCheckout}
          className="w-full bg-green-600 text-white py-4 px-6 rounded-xl text-lg font-semibold hover:bg-green-700 transition-colors shadow-lg"
        >
          {user ? '🛒 Proceed to Checkout' : 'Login to Checkout'}
        </button>
      </div>
      
      {/* Suggested Products */}
      <div className="mb-8">
        <h2 className="text-2xl font-bold mb-6">You might also like</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {products.map(product => {
            const hasDiscount = product.originalPrice && product.discountPercentage && product.discountPercentage > 0;
            return (
              <div key={product._id} className="bg-white rounded-lg shadow hover:shadow-lg transition-shadow">
                <Link to={`/product/${product._id}`}>
                  <img 
                    src={product.imageUrl} 
                    alt={product.name}
                    className="w-full h-48 object-cover rounded-t-lg"
                  />
                </Link>
                <div className="p-4">
                  <Link to={`/product/${product._id}`}>
                    <h3 className="font-semibold text-lg mb-2 hover:text-blue-600">{product.name}</h3>
                    <p className="text-gray-600 text-sm mb-2">{product.description.substring(0, 100)}...</p>
                  </Link>
                  
                  {/* Rating */}
                  <div className="flex items-center mb-2">
                    <div className="flex text-yellow-400 text-sm">
                      {'★'.repeat(Math.floor(product.averageRating || 0))}{'☆'.repeat(5 - Math.floor(product.averageRating || 0))}
                    </div>
                    <span className="text-gray-500 text-xs ml-1">({product.totalRatings || 0})</span>
                  </div>
                  
                  {/* Price */}
                  <div className="flex items-center space-x-2 mb-3">
                    <span className="text-xl font-bold text-green-600">₹{product.price.toLocaleString()}</span>
                    {hasDiscount && (
                      <>
                        <span className="text-sm text-gray-500 line-through">₹{product.originalPrice.toLocaleString()}</span>
                        <span className="bg-red-100 text-red-800 text-xs px-1 py-0.5 rounded">{product.discountPercentage}% OFF</span>
                      </>
                    )}
                  </div>
                  
                  <button 
                    onClick={() => handleAddToCart(product)}
                    className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    Add to Cart
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// Login Page Component
function LoginPage({ login, user }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (user) {
      const from = location.state?.from?.pathname || '/';
      navigate(from);
    }
  }, [user, navigate, location]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    if (isLogin) {
      const success = await login(email, password);
      if (success) {
        const from = location.state?.from?.pathname || '/';
        navigate(from);
      } else {
        alert('Login failed. Please check your credentials.');
      }
    } else {
      // Register logic
      try {
        const response = await fetch(`${API_BASE}/api/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password, name: email.includes('@') ? email.split('@')[0] : 'User' })
        });
        
        if (response.status === 429) {
          alert('Too many registration attempts. Please wait 15 minutes and try again.');
          setLoading(false);
          return;
        }
        
        if (response.ok) {
          alert('Registration successful! Please login.');
          setIsLogin(true);
          setPassword('');
        } else {
          const data = await response.json().catch(() => ({ error: 'Registration failed' }));
          alert(data.error || 'Registration failed. Please try again.');
        }
      } catch (error) {
        console.error('Registration error:', error);
        alert('Registration failed. Please try again.');
      }
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 flex items-center justify-center py-12 px-4">
      <div className="max-w-md w-full">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-20 h-20 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-full flex items-center justify-center mx-auto mb-4 shadow-lg">
            <span className="text-3xl text-white">{isLogin ? '🔐' : '👋'}</span>
          </div>
          <h1 className="text-4xl font-bold text-gray-800 mb-2">
            {isLogin ? 'Welcome Back!' : 'Join SamriddhiShop'}
          </h1>
          <p className="text-gray-600">
            {isLogin ? 'Sign in to your account to continue' : 'Create your account to get started'}
          </p>
        </div>

        {/* Form Card */}
        <div className="bg-white rounded-2xl shadow-xl p-8 border border-gray-100">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                📧 Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 bg-gray-50 focus:bg-white"
                placeholder="Enter your email address"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                🔒 Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 bg-gray-50 focus:bg-white"
                placeholder={isLogin ? 'Enter your password' : 'Create a strong password'}
                required
              />
            </div>
            
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-4 rounded-xl font-semibold hover:from-blue-700 hover:to-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5"
            >
              {loading ? (
                <span className="flex items-center justify-center space-x-2">
                  <span className="animate-spin">⏳</span>
                  <span>{isLogin ? 'Signing In...' : 'Creating Account...'}</span>
                </span>
              ) : (
                <span className="flex items-center justify-center space-x-2">
                  <span>{isLogin ? '🚀' : '✨'}</span>
                  <span>{isLogin ? 'Sign In' : 'Create Account'}</span>
                </span>
              )}
            </button>
          </form>
          
          {/* Toggle Form */}
          <div className="mt-8 text-center">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-4 bg-white text-gray-500">or</span>
              </div>
            </div>
            
            <p className="mt-4 text-gray-600">
              {isLogin ? "Don't have an account?" : "Already have an account?"}
            </p>
            <button
              onClick={() => {
                setIsLogin(!isLogin);
                setPassword('');
              }}
              className="mt-2 text-blue-600 hover:text-blue-800 font-semibold transition-colors duration-200 hover:underline"
            >
              {isLogin ? '🎯 Create New Account' : '🔑 Sign In Instead'}
            </button>
          </div>
        </div>

        {/* Features */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-4 text-center">
          <div className="bg-white/60 backdrop-blur-sm p-4 rounded-xl">
            <div className="text-2xl mb-2">🛡️</div>
            <p className="text-sm text-gray-600 font-medium">Secure & Safe</p>
          </div>
          <div className="bg-white/60 backdrop-blur-sm p-4 rounded-xl">
            <div className="text-2xl mb-2">🚚</div>
            <p className="text-sm text-gray-600 font-medium">Fast Delivery</p>
          </div>
          <div className="bg-white/60 backdrop-blur-sm p-4 rounded-xl">
            <div className="text-2xl mb-2">💎</div>
            <p className="text-sm text-gray-600 font-medium">Quality Products</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// Order History Component
function OrderHistory({ user }) {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) {
      fetchOrders();
    }
  }, [user]);

  const fetchOrders = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/orders`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setOrders(data);
    } catch (error) {
      console.error('Error fetching orders:', error);
    }
    setLoading(false);
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">Order History</h2>
      {orders.length === 0 ? (
        <div className="text-center py-8">
          <p className="text-gray-600 mb-4">No orders yet.</p>
          <Link to="/products" className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
            Start Shopping
          </Link>
        </div>
      ) : (
        <div className="space-y-4">
          {orders.map(order => (
            <div key={order._id} className="border p-4 rounded">
              <div className="flex justify-between items-center mb-2">
                <span className="font-semibold">Order #{order.orderNumber || order._id}</span>
                <span className="text-green-600 font-bold">₹{order.total.toFixed(2)}</span>
              </div>
              <p className="text-sm text-gray-600">
                {new Date(order.createdAt).toLocaleDateString()}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Product Card Component
const ProductCard = React.memo(function ProductCard({ product }) {
  const hasDiscount = product.originalPrice && product.discountPercentage && product.discountPercentage > 0;
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const [imageLoaded, setImageLoaded] = useState(false);
  const images = [product.imageUrl, ...(product.images || [])].filter(Boolean);
  
  useEffect(() => {
    if (images.length > 1) {
      const interval = setInterval(() => {
        setCurrentImageIndex(prev => (prev + 1) % images.length);
      }, 5000);
      return () => clearInterval(interval);
    }
  }, [images.length]);
  
  return (
    <Link to={`/product/${product._id}`} className="bg-white rounded-lg shadow hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2 group block">
      <div className="relative overflow-hidden rounded-t-lg aspect-[4/3]">
        <img 
          src={images[currentImageIndex]} 
          alt={product.name}
          className="w-full h-96 object-cover transition-all duration-300 group-hover:scale-105"
          loading="lazy"
          width="300"
          height="384"
          onLoad={() => setImageLoaded(true)}
          style={{ opacity: imageLoaded ? 1 : 0 }}
        />
        {!imageLoaded && <div className="absolute inset-0 bg-gray-300 animate-pulse w-full h-96" />}
        {hasDiscount && (
          <div className="absolute top-2 left-2 bg-red-500 text-white px-2 py-1 rounded text-xs font-bold">
            {product.discountPercentage}% OFF
          </div>
        )}
        {images.length > 1 && (
          <div className="absolute bottom-2 left-1/2 transform -translate-x-1/2 flex space-x-1">
            {images.map((_, index) => (
              <div
                key={index}
                className={`w-1.5 h-1.5 rounded-full ${
                  index === currentImageIndex ? 'bg-white' : 'bg-white bg-opacity-50'
                }`}
              />
            ))}
          </div>
        )}
      </div>
      <div className="px-3 pb-3">
        <h3 className="font-semibold text-lg group-hover:text-blue-600 transition-colors">{product.name}</h3>
        <p className="text-gray-600 text-sm mb-2">{product.description.substring(0, 100)}...</p>
        
        {/* Rating */}
        <div className="flex items-center mb-2">
          <div className="flex text-yellow-400 text-sm">
            {'★'.repeat(Math.floor(product.averageRating || 0))}{'☆'.repeat(5 - Math.floor(product.averageRating || 0))}
          </div>
          <span className="text-gray-500 text-xs ml-1">({product.totalRatings || 0})</span>
        </div>
        
        {/* Price */}
        <div className="flex items-center space-x-2">
          <span className="text-xl font-bold text-green-600">₹{product.price.toLocaleString()}</span>
          {hasDiscount && (
            <>
              <span className="text-sm text-gray-500 line-through">₹{product.originalPrice.toLocaleString()}</span>
            </>
          )}
        </div>
      </div>
    </Link>
  );
});

// Loading Spinner Component
const LoadingSpinner = React.memo(function LoadingSpinner() {
  return (
    <div className="flex justify-center items-center py-12 min-h-[200px]">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
    </div>
  );
});

// Order Status Page Component
function OrderStatusPageComponent({ user }) {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user) {
      fetchOrders();
    }
  }, [user]);

  const fetchOrders = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/orders`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setOrders(data);
    } catch (error) {
      console.error('Error fetching orders:', error);
    }
    setLoading(false);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending': return 'bg-yellow-100 text-yellow-800';
      case 'processing': return 'bg-blue-100 text-blue-800';
      case 'shipped': return 'bg-purple-100 text-purple-800';
      case 'delivered': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  if (!user) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-gray-600 mb-4">Please login to view your orders</h2>
        <Link to="/login" className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
          Login
        </Link>
      </div>
    );
  }

  if (loading) return <LoadingSpinner />;

  return (
    <div className="max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mb-8">My Orders</h1>
      
      {orders.length === 0 ? (
        <div className="text-center py-12">
          <h2 className="text-xl text-gray-600 mb-4">No orders found</h2>
          <Link to="/products" className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
            Start Shopping
          </Link>
        </div>
      ) : (
        <div className="space-y-6">
          {orders.map(order => (
            <div key={order._id} className="bg-white p-6 rounded-lg shadow border">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="text-lg font-semibold">Order #{order.orderNumber || order._id.slice(-8)}</h3>
                  <p className="text-gray-600">Placed on {new Date(order.createdAt).toLocaleDateString('en-IN')}</p>
                </div>
                <div className="text-right">
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(order.status)}`}>
                    {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
                  </span>
                  <p className="text-xl font-bold text-green-600 mt-2">₹{order.total.toFixed(2)}</p>
                </div>
              </div>
              
              <div className="border-t pt-4">
                <h4 className="font-medium mb-3">Order Items:</h4>
                <div className="space-y-2">
                  {order.items.map((item, index) => (
                    <div key={index} className="flex justify-between items-center py-2 border-b border-gray-100 last:border-b-0">
                      <div>
                        <span className="font-medium">{item.name}</span>
                        {item.selectedVariant && (
                          <span className="text-blue-600 text-sm ml-2">({item.selectedVariant.size} - {item.selectedVariant.color})</span>
                        )}
                        <span className="text-gray-600 ml-2">x{item.quantity}</span>
                      </div>
                      <span className="font-medium">₹{(item.price * item.quantity).toFixed(2)}</span>
                    </div>
                  ))}
                </div>
                
                {/* Order Summary */}
                <div className="mt-4 pt-4 border-t space-y-2">
                  <div className="flex justify-between text-gray-600">
                    <span>Subtotal</span>
                    <span>₹{order.items.reduce((sum, item) => sum + (item.price * item.quantity), 0).toFixed(2)}</span>
                  </div>
                  
                  {order.shippingCost > 0 && (
                    <div className="flex justify-between text-gray-600">
                      <span>Shipping</span>
                      <span>₹{order.shippingCost.toFixed(2)}</span>
                    </div>
                  )}
                  
                  {order.tax && (
                    <div className="flex justify-between text-gray-600">
                      <span>Tax (18%)</span>
                      <span>₹{order.tax.toFixed(2)}</span>
                    </div>
                  )}
                  
                  {order.couponCode && order.discount && (
                    <div className="flex justify-between text-green-600">
                      <span>Discount ({order.couponCode})</span>
                      <span>-₹{order.discount.toFixed(2)}</span>
                    </div>
                  )}
                  
                  <div className="flex justify-between items-center pt-2 border-t font-semibold">
                    <span>Total Paid</span>
                    <span className="text-green-600">₹{order.total.toFixed(2)}</span>
                  </div>
                </div>
              </div>
              
              <div className="mt-4 pt-4 border-t">
                <div className="flex justify-between items-center">
                  <div className="text-sm text-gray-600">
                    {order.status === 'delivered' && (
                      <span className="text-green-600 font-medium">✓ Delivered</span>
                    )}
                    {order.status === 'shipped' && (
                      <span className="text-purple-600 font-medium">🚚 In Transit</span>
                    )}
                    {order.status === 'processing' && (
                      <span className="text-blue-600 font-medium">⏳ Processing</span>
                    )}
                    {order.status === 'pending' && (
                      <span className="text-yellow-600 font-medium">📋 Order Confirmed</span>
                    )}
                  </div>
                  <Link to={`/track/${order._id}`} className="text-blue-500 hover:text-blue-700 font-medium">
                    Track Order
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Profile Page Component
function ProfilePageComponent({ user, setUser }) {
  const [activeTab, setActiveTab] = useState('profile');
  const [profile, setProfile] = useState({ name: '', email: '', phone: '' });
  const [passwords, setPasswords] = useState({ current: '', new: '', confirm: '' });
  const [addresses, setAddresses] = useState([]);
  const [newAddress, setNewAddress] = useState({ street: '', city: '', state: '', zipCode: '', country: 'India' });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (user) {
      fetchProfile();
    }
  }, [user]);

  const fetchProfile = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/profile`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setProfile({ name: data.name, email: data.email, phone: data.phone || '' });
      setAddresses(data.addresses || []);
    } catch (error) {
      console.error('Error fetching profile:', error);
    }
  };

  const updateProfile = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(profile)
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setUser(data.user);
        localStorage.setItem('user', JSON.stringify(data.user));
        alert('Profile updated successfully!');
      } else {
        alert(data.error || 'Failed to update profile');
      }
    } catch (error) {
      console.error('Profile update error:', error);
      alert('Failed to update profile');
    }
    setLoading(false);
  };

  const changePassword = async () => {
    if (passwords.new !== passwords.confirm) {
      alert('New passwords do not match');
      return;
    }
    
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/change-password`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ currentPassword: passwords.current, newPassword: passwords.new })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        alert('Password changed successfully!');
        setPasswords({ current: '', new: '', confirm: '' });
      } else {
        alert(data.error || 'Failed to change password');
      }
    } catch (error) {
      console.error('Password change error:', error);
      alert('Failed to change password');
    }
    setLoading(false);
  };

  const addAddress = async () => {
    if (!newAddress.street || !newAddress.city) {
      alert('Please fill in required fields');
      return;
    }
    
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/addresses`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(newAddress)
      });
      
      const data = await response.json();
      
      if (response.ok) {
        await fetchProfile();
        setNewAddress({ street: '', city: '', state: '', zipCode: '', country: 'India' });
        alert('Address added successfully!');
      } else {
        alert(data.error || 'Failed to add address');
      }
    } catch (error) {
      console.error('Add address error:', error);
      alert('Failed to add address');
    }
    setLoading(false);
  };

  const deleteAddress = async (addressId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/addresses/${addressId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      const data = await response.json();
      
      if (response.ok) {
        await fetchProfile();
        alert('Address deleted successfully!');
      } else {
        alert(data.error || 'Failed to delete address');
      }
    } catch (error) {
      console.error('Delete address error:', error);
      alert('Failed to delete address');
    }
  };

  const tabs = [
    { id: 'profile', label: 'Profile', icon: '👤' },
    { id: 'orders', label: 'Orders', icon: '📦' },
    { id: 'password', label: 'Security', icon: '🔒' },
    { id: 'addresses', label: 'Addresses', icon: '📍' }
  ];

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
        <div className="bg-white p-8 rounded-2xl shadow-xl text-center max-w-md w-full mx-4">
          <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <span className="text-2xl">🔐</span>
          </div>
          <h2 className="text-2xl font-bold text-gray-800 mb-2">Authentication Required</h2>
          <p className="text-gray-600 mb-6">Please login to access your profile</p>
          <Link to="/login" className="bg-gradient-to-r from-blue-600 to-indigo-600 text-white px-8 py-3 rounded-xl font-semibold hover:from-blue-700 hover:to-indigo-700 transition-all duration-200 shadow-lg hover:shadow-xl">
            Login to Continue
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50 py-8">
      <div className="max-w-6xl mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-20 h-20 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-full flex items-center justify-center mx-auto mb-4 shadow-lg">
            <span className="text-3xl text-white">👤</span>
          </div>
          <h1 className="text-4xl font-bold text-gray-800 mb-2">My Profile</h1>
          <p className="text-gray-600">Manage your account settings and preferences</p>
        </div>
        
        <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
          {/* Navigation Tabs */}
          <div className="bg-gradient-to-r from-gray-50 to-blue-50 border-b border-gray-200">
            <nav className="flex overflow-x-auto">
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 px-6 py-4 font-medium text-sm whitespace-nowrap transition-all duration-200 ${
                    activeTab === tab.id
                      ? 'border-b-3 border-blue-600 text-blue-600 bg-white shadow-sm'
                      : 'text-gray-600 hover:text-gray-800 hover:bg-white/50'
                  }`}
                >
                  <span className="text-lg">{tab.icon}</span>
                  <span>{tab.label}</span>
                </button>
              ))}
            </nav>
          </div>
          
          <div className="p-8">
            {activeTab === 'profile' && (
              <div className="space-y-8">
                {/* Welcome Card */}
                <div className="bg-gradient-to-r from-blue-600 to-indigo-600 text-white p-6 rounded-xl shadow-lg">
                  <div className="flex items-center space-x-4">
                    <div className="w-16 h-16 bg-white/20 rounded-full flex items-center justify-center">
                      <span className="text-2xl">👋</span>
                    </div>
                    <div>
                      <h2 className="text-2xl font-bold">Welcome back, {user.name}!</h2>
                      <p className="text-blue-100">Member since {new Date(user.createdAt || Date.now()).toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}</p>
                    </div>
                  </div>
                </div>
                
                {/* Profile Stats */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-gradient-to-br from-green-50 to-emerald-50 p-6 rounded-xl border border-green-200">
                    <div className="flex items-center space-x-3">
                      <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                        <span className="text-xl">📧</span>
                      </div>
                      <div>
                        <p className="text-sm text-green-600 font-medium">Email</p>
                        <p className="text-green-800 font-semibold">{user.email}</p>
                      </div>
                    </div>
                  </div>
                  <div className="bg-gradient-to-br from-purple-50 to-violet-50 p-6 rounded-xl border border-purple-200">
                    <div className="flex items-center space-x-3">
                      <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
                        <span className="text-xl">📱</span>
                      </div>
                      <div>
                        <p className="text-sm text-purple-600 font-medium">Phone</p>
                        <p className="text-purple-800 font-semibold">{user.phone || 'Not provided'}</p>
                      </div>
                    </div>
                  </div>
                  <div className="bg-gradient-to-br from-orange-50 to-amber-50 p-6 rounded-xl border border-orange-200">
                    <div className="flex items-center space-x-3">
                      <div className="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center">
                        <span className="text-xl">🛡️</span>
                      </div>
                      <div>
                        <p className="text-sm text-orange-600 font-medium">Account Status</p>
                        <p className="text-orange-800 font-semibold">Verified</p>
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Update Profile Form */}
                <div className="bg-gray-50 p-6 rounded-xl">
                  <h3 className="text-xl font-bold text-gray-800 mb-6 flex items-center space-x-2">
                    <span>✏️</span>
                    <span>Update Profile Information</span>
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-semibold text-gray-700 mb-2">Full Name</label>
                      <input
                        type="text"
                        value={profile.name}
                        onChange={(e) => setProfile({...profile, name: e.target.value})}
                        className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                        placeholder="Enter your full name"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-semibold text-gray-700 mb-2">Email Address</label>
                      <input
                        type="email"
                        value={profile.email}
                        onChange={(e) => setProfile({...profile, email: e.target.value})}
                        className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                        placeholder="Enter your email"
                      />
                    </div>
                    <div className="md:col-span-2">
                      <label className="block text-sm font-semibold text-gray-700 mb-2">Phone Number</label>
                      <input
                        type="tel"
                        value={profile.phone}
                        onChange={(e) => setProfile({...profile, phone: e.target.value})}
                        className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                        placeholder="+91 9876543210"
                      />
                    </div>
                  </div>
                  <button
                    onClick={updateProfile}
                    disabled={loading}
                    className="mt-6 bg-gradient-to-r from-blue-600 to-indigo-600 text-white px-8 py-3 rounded-xl font-semibold hover:from-blue-700 hover:to-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg hover:shadow-xl"
                  >
                    {loading ? (
                      <span className="flex items-center space-x-2">
                        <span className="animate-spin">⏳</span>
                        <span>Updating...</span>
                      </span>
                    ) : (
                      <span className="flex items-center space-x-2">
                        <span>💾</span>
                        <span>Save Changes</span>
                      </span>
                    )}
                  </button>
                </div>
              </div>
            )}
            
            {activeTab === 'orders' && (
              <div>
                <div className="flex items-center space-x-3 mb-6">
                  <span className="text-2xl">📦</span>
                  <h2 className="text-2xl font-bold text-gray-800">Order History</h2>
                </div>
                <OrderHistory user={user} />
              </div>
            )}
            
            {activeTab === 'password' && (
              <div className="max-w-md mx-auto">
                <div className="text-center mb-8">
                  <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <span className="text-2xl">🔒</span>
                  </div>
                  <h2 className="text-2xl font-bold text-gray-800 mb-2">Security Settings</h2>
                  <p className="text-gray-600">Update your password to keep your account secure</p>
                </div>
                
                <div className="bg-gray-50 p-6 rounded-xl space-y-6">
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Current Password</label>
                    <input
                      type="password"
                      value={passwords.current}
                      onChange={(e) => setPasswords({...passwords, current: e.target.value})}
                      className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-all duration-200"
                      placeholder="Enter current password"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">New Password</label>
                    <input
                      type="password"
                      value={passwords.new}
                      onChange={(e) => setPasswords({...passwords, new: e.target.value})}
                      className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-all duration-200"
                      placeholder="Enter new password"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Confirm New Password</label>
                    <input
                      type="password"
                      value={passwords.confirm}
                      onChange={(e) => setPasswords({...passwords, confirm: e.target.value})}
                      className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-all duration-200"
                      placeholder="Confirm new password"
                    />
                  </div>
                  <button
                    onClick={changePassword}
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-red-600 to-pink-600 text-white px-6 py-3 rounded-xl font-semibold hover:from-red-700 hover:to-pink-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg hover:shadow-xl"
                  >
                    {loading ? (
                      <span className="flex items-center justify-center space-x-2">
                        <span className="animate-spin">⏳</span>
                        <span>Updating...</span>
                      </span>
                    ) : (
                      <span className="flex items-center justify-center space-x-2">
                        <span>🔐</span>
                        <span>Update Password</span>
                      </span>
                    )}
                  </button>
                </div>
              </div>
            )}
            
            {activeTab === 'addresses' && (
              <div className="space-y-8">
                <div className="flex items-center space-x-3">
                  <span className="text-2xl">📍</span>
                  <h2 className="text-2xl font-bold text-gray-800">Delivery Addresses</h2>
                </div>
                
                {/* Saved Addresses */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {addresses.map(address => (
                    <div key={address._id} className="bg-gradient-to-br from-blue-50 to-indigo-50 p-6 rounded-xl border border-blue-200 relative group hover:shadow-lg transition-all duration-200">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-3">
                            <span className="text-lg">🏠</span>
                            <span className="font-semibold text-blue-800">Delivery Address</span>
                          </div>
                          <p className="font-medium text-gray-800 mb-1">{address.street}</p>
                          <p className="text-gray-600 mb-1">{address.city}, {address.state}</p>
                          <p className="text-gray-600">{address.zipCode}, {address.country}</p>
                        </div>
                        <button
                          onClick={() => deleteAddress(address._id)}
                          className="text-red-500 hover:text-red-700 hover:bg-red-50 p-2 rounded-lg transition-all duration-200 opacity-0 group-hover:opacity-100"
                          title="Delete address"
                        >
                          🗑️
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
                
                {/* Add New Address */}
                <div className="bg-gray-50 p-6 rounded-xl">
                  <h3 className="text-xl font-bold text-gray-800 mb-6 flex items-center space-x-2">
                    <span>➕</span>
                    <span>Add New Address</span>
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <input
                      type="text"
                      placeholder="Street Address *"
                      value={newAddress.street}
                      onChange={(e) => setNewAddress({...newAddress, street: e.target.value})}
                      className="px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
                    />
                    <input
                      type="text"
                      placeholder="City *"
                      value={newAddress.city}
                      onChange={(e) => setNewAddress({...newAddress, city: e.target.value})}
                      className="px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
                    />
                    <input
                      type="text"
                      placeholder="State"
                      value={newAddress.state}
                      onChange={(e) => setNewAddress({...newAddress, state: e.target.value})}
                      className="px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
                    />
                    <input
                      type="text"
                      placeholder="ZIP Code"
                      value={newAddress.zipCode}
                      onChange={(e) => setNewAddress({...newAddress, zipCode: e.target.value})}
                      className="px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
                    />
                  </div>
                  <button
                    onClick={addAddress}
                    disabled={loading}
                    className="mt-6 bg-gradient-to-r from-green-600 to-emerald-600 text-white px-8 py-3 rounded-xl font-semibold hover:from-green-700 hover:to-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg hover:shadow-xl"
                  >
                    {loading ? (
                      <span className="flex items-center space-x-2">
                        <span className="animate-spin">⏳</span>
                        <span>Adding...</span>
                      </span>
                    ) : (
                      <span className="flex items-center space-x-2">
                        <span>📍</span>
                        <span>Add Address</span>
                      </span>
                    )}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Track Order Page Component
function TrackOrderPageComponent({ user }) {
  const { orderId } = useParams();
  const [order, setOrder] = useState(null);
  const [trackingHistory, setTrackingHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    if (user && orderId) {
      fetchOrderDetails();
    }
  }, [user, orderId]);

  const fetchOrderDetails = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/orders/${orderId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setOrder(data);
        generateTrackingHistory(data);
      } else {
        alert('Order not found');
        navigate('/orders');
      }
    } catch (error) {
      console.error('Error fetching order:', error);
      alert('Failed to fetch order details');
      navigate('/orders');
    }
    setLoading(false);
  };

  const generateTrackingHistory = (orderData) => {
    const baseDate = new Date(orderData.createdAt);
    const shippedDate = orderData.courierDetails?.shippedAt ? new Date(orderData.courierDetails.shippedAt) : new Date(baseDate.getTime() + 24 * 60 * 60 * 1000);
    const expectedDelivery = orderData.courierDetails?.estimatedDelivery ? new Date(orderData.courierDetails.estimatedDelivery) : new Date(baseDate.getTime() + 3 * 24 * 60 * 60 * 1000);
    
    const history = [
      {
        status: 'pending',
        title: 'Order Placed',
        description: 'Your order has been successfully placed and is being processed.',
        date: baseDate,
        completed: true
      }
    ];

    if (['processing', 'shipped', 'delivered'].includes(orderData.status)) {
      history.push({
        status: 'processing',
        title: 'Order Confirmed',
        description: 'Your order has been confirmed and is being prepared for shipment.',
        date: new Date(baseDate.getTime() + 2 * 60 * 60 * 1000),
        completed: true
      });
    }

    if (['shipped', 'delivered'].includes(orderData.status)) {
      history.push({
        status: 'shipped',
        title: 'Order Shipped',
        description: 'Your order has been shipped and is on its way to you.',
        date: shippedDate,
        completed: true
      });
    }

    if (orderData.status === 'delivered') {
      history.push({
        status: 'delivered',
        title: 'Order Delivered',
        description: 'Your order has been successfully delivered.',
        date: expectedDelivery,
        completed: true
      });
    } else {
      if (orderData.status === 'shipped') {
        history.push({
          status: 'out-for-delivery',
          title: 'Out for Delivery',
          description: 'Your order is out for delivery and will arrive soon.',
          date: expectedDelivery,
          completed: false,
          estimated: true
        });
      }
      
      history.push({
        status: 'delivered',
        title: 'Delivered',
        description: 'Your order will be delivered to your address.',
        date: expectedDelivery,
        completed: false,
        estimated: true
      });
    }

    setTrackingHistory(history);
  };

  const getStatusIcon = (status, completed) => {
    if (completed) {
      return '✅';
    }
    switch (status) {
      case 'pending': return '📋';
      case 'processing': return '⏳';
      case 'shipped': return '🚚';
      case 'out-for-delivery': return '🚛';
      case 'delivered': return '📦';
      default: return '⭕';
    }
  };

  const getStatusColor = (status, completed) => {
    if (completed) return 'text-green-600';
    if (status === order?.status) return 'text-blue-600';
    return 'text-gray-400';
  };

  if (!user) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-gray-600 mb-4">Please login to track orders</h2>
        <Link to="/login" className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
          Login
        </Link>
      </div>
    );
  }

  if (loading) return <LoadingSpinner />;

  if (!order) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-gray-600 mb-4">Order not found</h2>
        <Link to="/orders" className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
          Back to Orders
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="mb-6">
        <button 
          onClick={() => navigate('/orders')}
          className="text-blue-500 hover:text-blue-700 mb-4"
        >
          ← Back to Orders
        </button>
        <h1 className="text-3xl font-bold">Track Order #{order.orderNumber || order._id.slice(-8)}</h1>
      </div>

      {/* Order Summary */}
      <div className="bg-white p-6 rounded-lg shadow mb-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <h3 className="font-semibold text-gray-700 mb-2">Order Details</h3>
            <p><strong>Order ID:</strong> #{order.orderNumber || order._id.slice(-8)}</p>
            <p><strong>Order Date:</strong> {new Date(order.createdAt).toLocaleDateString('en-IN')}</p>
            <p><strong>Total Amount:</strong> ₹{order.total.toFixed(2)}</p>
          </div>
          
          <div>
            <h3 className="font-semibold text-gray-700 mb-2">Current Status</h3>
            <div className="flex items-center space-x-2">
              <span className="text-2xl">{getStatusIcon(order.status, true)}</span>
              <span className="font-medium capitalize text-lg">{order.status}</span>
            </div>
            <p className="text-sm text-gray-600 mt-1">
              Last updated: {new Date(order.createdAt).toLocaleString('en-IN')}
            </p>
          </div>
          
          {order.shippingAddress && (
            <div>
              <h3 className="font-semibold text-gray-700 mb-2">Delivery Address</h3>
              <p className="text-sm">
                {order.shippingAddress.street}<br/>
                {order.shippingAddress.city}, {order.shippingAddress.state}<br/>
                {order.shippingAddress.zipCode}, {order.shippingAddress.country}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Courier & Tracking Details */}
      {order.courierDetails && (
        <div className="bg-blue-50 p-6 rounded-lg shadow mb-8">
          <h2 className="text-xl font-semibold text-blue-800 mb-4">🚚 Shipping & Tracking Details</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div>
              <h3 className="font-semibold text-blue-700 mb-2">Courier Partner</h3>
              <p className="text-lg font-medium text-blue-900">{order.courierDetails.courierName}</p>
            </div>
            
            <div>
              <h3 className="font-semibold text-blue-700 mb-2">Tracking Number</h3>
              <p className="text-lg font-mono bg-white px-3 py-2 rounded border text-blue-900">
                {order.courierDetails.trackingNumber}
              </p>
            </div>
            
            {order.courierDetails.shippedAt && (
              <div>
                <h3 className="font-semibold text-blue-700 mb-2">Shipped Date</h3>
                <p className="text-blue-900">
                  {new Date(order.courierDetails.shippedAt).toLocaleDateString('en-IN')}
                </p>
                <p className="text-sm text-blue-700">
                  {new Date(order.courierDetails.shippedAt).toLocaleTimeString('en-IN', { 
                    hour: '2-digit', 
                    minute: '2-digit' 
                  })}
                </p>
              </div>
            )}
            
            {order.courierDetails.estimatedDelivery && (
              <div>
                <h3 className="font-semibold text-blue-700 mb-2">Expected Delivery</h3>
                <p className="text-blue-900">
                  {new Date(order.courierDetails.estimatedDelivery).toLocaleDateString('en-IN')}
                </p>
                <p className="text-sm text-blue-700">Estimated</p>
              </div>
            )}
          </div>
          
          {/* Quick Tracking Links */}
          <div className="mt-6 pt-4 border-t border-blue-200">
            <h3 className="font-semibold text-blue-700 mb-3">Track Your Package</h3>
            <div className="flex flex-wrap gap-3">
              {order.courierDetails.courierName === 'Blue Dart' && (
                <a 
                  href={`https://www.bluedart.com/web/guest/trackdartresult?trackFor=0&trackNo=${order.courierDetails.trackingNumber}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors text-sm"
                >
                  Track on Blue Dart
                </a>
              )}
              {order.courierDetails.courierName === 'DTDC' && (
                <a 
                  href={`https://www.dtdc.in/tracking/tracking_results.asp?Ttype=awb_no&strCnno=${order.courierDetails.trackingNumber}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors text-sm"
                >
                  Track on DTDC
                </a>
              )}
              {order.courierDetails.courierName === 'FedEx' && (
                <a 
                  href={`https://www.fedex.com/fedextrack/?trknbr=${order.courierDetails.trackingNumber}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-purple-600 text-white px-4 py-2 rounded-lg hover:bg-purple-700 transition-colors text-sm"
                >
                  Track on FedEx
                </a>
              )}
              {order.courierDetails.courierName === 'Delhivery' && (
                <a 
                  href={`https://www.delhivery.com/track/package/${order.courierDetails.trackingNumber}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-orange-600 text-white px-4 py-2 rounded-lg hover:bg-orange-700 transition-colors text-sm"
                >
                  Track on Delhivery
                </a>
              )}
              <button
                onClick={() => navigator.clipboard.writeText(order.courierDetails.trackingNumber)}
                className="bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors text-sm"
              >
                📋 Copy Tracking Number
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tracking Timeline */}
      <div className="bg-white p-6 rounded-lg shadow mb-8">
        <h2 className="text-xl font-semibold mb-6">Tracking Timeline</h2>
        <div className="space-y-6">
          {trackingHistory.map((step, index) => (
            <div key={index} className="flex items-start space-x-4">
              <div className="flex flex-col items-center">
                <div className={`text-2xl ${getStatusColor(step.status, step.completed)}`}>
                  {getStatusIcon(step.status, step.completed)}
                </div>
                {index < trackingHistory.length - 1 && (
                  <div className={`w-0.5 h-12 mt-2 ${
                    step.completed ? 'bg-green-300' : 'bg-gray-300'
                  }`}></div>
                )}
              </div>
              
              <div className="flex-1">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className={`font-semibold ${
                      step.completed ? 'text-green-600' : 
                      step.status === order.status ? 'text-blue-600' : 'text-gray-400'
                    }`}>
                      {step.title}
                    </h3>
                    <p className={`text-sm mt-1 ${
                      step.completed ? 'text-gray-700' : 'text-gray-500'
                    }`}>
                      {step.description}
                    </p>
                  </div>
                  
                  <div className="text-right">
                    <p className={`text-sm ${
                      step.completed ? 'text-gray-600' : 'text-gray-400'
                    }`}>
                      {step.estimated ? 'Expected: ' : ''}
                      {step.date.toLocaleDateString('en-IN')}
                    </p>
                    <p className={`text-xs ${
                      step.completed ? 'text-gray-500' : 'text-gray-400'
                    }`}>
                      {step.completed ? step.date.toLocaleTimeString('en-IN', { 
                        hour: '2-digit', 
                        minute: '2-digit' 
                      }) : ''}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Order Items */}
      <div className="bg-white p-6 rounded-lg shadow">
        <h2 className="text-xl font-semibold mb-4">Order Items</h2>
        <div className="space-y-4">
          {order.items.map((item, index) => (
            <div key={index} className="flex justify-between items-center py-3 border-b border-gray-100 last:border-b-0">
              <div>
                <h3 className="font-medium">{item.name}</h3>
                {item.selectedVariant && (
                  <p className="text-sm text-blue-600">{item.selectedVariant.size} - {item.selectedVariant.color}</p>
                )}
                <p className="text-sm text-gray-600">Quantity: {item.quantity}</p>
              </div>
              <div className="text-right">
                <p className="font-medium">₹{(item.price * item.quantity).toFixed(2)}</p>
                <p className="text-sm text-gray-600">₹{item.price} each</p>
              </div>
            </div>
          ))}
          
          <div className="pt-4 border-t space-y-2">
            <div className="flex justify-between text-gray-600">
              <span>Subtotal</span>
              <span>₹{order.items.reduce((sum, item) => sum + (item.price * item.quantity), 0).toFixed(2)}</span>
            </div>
            
            {order.shippingCost > 0 && (
              <div className="flex justify-between text-gray-600">
                <span>Shipping</span>
                <span>₹{order.shippingCost.toFixed(2)}</span>
              </div>
            )}
            
            {order.tax && (
              <div className="flex justify-between text-gray-600">
                <span>Tax (18%)</span>
                <span>₹{order.tax.toFixed(2)}</span>
              </div>
            )}
            
            {order.couponCode && order.discount && (
              <div className="flex justify-between text-green-600">
                <span>Discount ({order.couponCode})</span>
                <span>-₹{order.discount.toFixed(2)}</span>
              </div>
            )}
            
            <div className="flex justify-between items-center pt-2 border-t">
              <span className="text-lg font-semibold">Total Paid</span>
              <span className="text-lg font-bold text-green-600">₹{order.total.toFixed(2)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Help Section */}
      <div className="mt-8 bg-blue-50 p-6 rounded-lg">
        <h3 className="font-semibold text-blue-800 mb-2">Need Help?</h3>
        <p className="text-blue-700 text-sm mb-3">
          If you have any questions about your order or delivery, please contact our support team.
        </p>
        <div className="flex space-x-4">
          <button className="bg-blue-500 text-white px-4 py-2 rounded text-sm hover:bg-blue-600">
            Contact Support
          </button>
          <button className="border border-blue-500 text-blue-500 px-4 py-2 rounded text-sm hover:bg-blue-50">
            Report Issue
          </button>
        </div>
      </div>
    </div>
  );
}



// Admin Panel Component
function AdminPanelComponent({ user }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [products, setProducts] = useState([]);
  const [orders, setOrders] = useState([]);
  const [coupons, setCoupons] = useState([]);
  const [users, setUsers] = useState([]);
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [userFilters, setUserFilters] = useState({ search: '', userType: 'all', sortBy: 'name' });
  const [contacts, setContacts] = useState([]);
  const [shippingCost, setShippingCost] = useState(0);
  const [loading, setLoading] = useState(false);
  const [analytics, setAnalytics] = useState({});
  const [dateFilter, setDateFilter] = useState({ startDate: '', endDate: '', status: 'all' });
  const [selectedOrder, setSelectedOrder] = useState(null);
  const [courierForm, setCourierForm] = useState({ courierName: '', trackingNumber: '', estimatedDelivery: '', notes: '' });
  
  // Product form state
  const [productForm, setProductForm] = useState({
    name: '', description: '', price: '', originalPrice: '', discountPercentage: '', imageUrl: '', category: '', stock: '', variants: [],
    highlights: [], specifications: [], warranty: '', images: [],
    showHighlights: false, showSpecifications: false, showWarranty: false
  });
  const [newVariant, setNewVariant] = useState({ size: '', color: '', stock: '' });
  const [newHighlight, setNewHighlight] = useState('');
  const [newSpec, setNewSpec] = useState({ key: '', value: '' });
  const [showProductForm, setShowProductForm] = useState(false);
  const [editingProduct, setEditingProduct] = useState(null);
  
  // Coupon form state
  const [couponForm, setCouponForm] = useState({
    code: '', discount: '', type: 'percentage', minAmount: '', maxDiscount: '', expiryDate: '', oneTimeUse: false
  });
  const [couponReport, setCouponReport] = useState([]);
  const [showReport, setShowReport] = useState(false);
  const [bannerForm, setBannerForm] = useState({
    title: '', subtitle: '', buttonText: '', backgroundImage: ''
  });
  const [adminNotification, setAdminNotification] = useState(null);

  useEffect(() => {
    if (user?.email !== 'admin@samriddhishop.com') {
      alert('Access denied. Admin only.');
      return;
    }
    fetchData();
  }, [user]);

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token');
      const [productsRes, ordersRes, couponsRes, usersRes, contactsRes, shippingRes, analyticsRes, bannerRes] = await Promise.all([
        fetch(`${API_BASE}/api/admin/products`, { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch(`${API_BASE}/api/admin/orders`, { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch(`${API_BASE}/api/admin/coupons`, { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch(`${API_BASE}/api/admin/users`, { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch(`${API_BASE}/api/admin/contacts`, { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch(`${API_BASE}/api/shipping-cost`),
        fetch(`${API_BASE}/api/admin/analytics`, { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch(`${API_BASE}/api/banner`)
      ]);
      
      setProducts(await productsRes.json());
      setOrders(await ordersRes.json());
      setCoupons(await couponsRes.json());
      const userData = await usersRes.json();
      setUsers(userData);
      setFilteredUsers(userData);
      setContacts(await contactsRes.json());
      setShippingCost((await shippingRes.json()).cost || 0);
      setAnalytics(await analyticsRes.json());
      const bannerData = await bannerRes.json();
      setBannerForm({
        title: bannerData.title || '',
        subtitle: bannerData.subtitle || '',
        buttonText: bannerData.buttonText || '',
        backgroundImage: bannerData.backgroundImage || ''
      });
    } catch (error) {
      console.error('Error fetching admin data:', error);
    }
  };

  const fetchOrdersByDate = async () => {
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams(dateFilter);
      const response = await fetch(`${API_BASE}/api/admin/orders/date-range?${params}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setOrders(data);
    } catch (error) {
      console.error('Error fetching filtered orders:', error);
    }
  };

  const saveProduct = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const url = editingProduct ? `${API_BASE}/api/admin/products/${editingProduct._id}` : `${API_BASE}/api/admin/products`;
      const method = editingProduct ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(productForm)
      });
      
      if (response.ok) {
        setAdminNotification({
          message: editingProduct ? 'Product updated successfully!' : 'Product added successfully!',
          type: 'success'
        });
        setTimeout(() => setAdminNotification(null), 3000);
        
        setShowProductForm(false);
        setProductForm({ name: '', description: '', price: '', originalPrice: '', discountPercentage: '', imageUrl: '', category: '', stock: '', variants: [], highlights: [], specifications: [], warranty: '', images: [], showHighlights: false, showSpecifications: false, showWarranty: false });
        setEditingProduct(null);
        fetchData();
      }
    } catch (error) {
      setAdminNotification({
        message: 'Failed to save product',
        type: 'error'
      });
      setTimeout(() => setAdminNotification(null), 3000);
    }
    setLoading(false);
  };

  const toggleProduct = async (productId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await fetch(`${API_BASE}/api/admin/products/${productId}/toggle`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ enabled: !enabled })
      });
      fetchData();
    } catch (error) {
      alert('Failed to toggle product');
    }
  };

  const updateOrderStatus = async (orderId, status, withCourier = false) => {
    try {
      const token = localStorage.getItem('token');
      const payload = { status };
      
      if (withCourier && status === 'shipped') {
        payload.courierName = courierForm.courierName;
        payload.trackingNumber = courierForm.trackingNumber;
        payload.estimatedDelivery = courierForm.estimatedDelivery;
        payload.notes = courierForm.notes;
      }
      
      await fetch(`${API_BASE}/api/orders/${orderId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload)
      });
      
      fetchData();
      setSelectedOrder(null);
      setCourierForm({ courierName: '', trackingNumber: '', estimatedDelivery: '', notes: '' });
      alert('Order status updated!');
    } catch (error) {
      alert('Failed to update order status');
    }
  };

  const handleStatusChange = (orderId, newStatus) => {
    if (newStatus === 'shipped') {
      setSelectedOrder(orderId);
    } else {
      updateOrderStatus(orderId, newStatus);
    }
  };

  const saveCoupon = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/admin/coupons`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(couponForm)
      });
      
      if (response.ok) {
        alert('Coupon created!');
        setCouponForm({ code: '', discount: '', type: 'percentage', minAmount: '', maxDiscount: '', expiryDate: '', oneTimeUse: false });
        fetchData();
      }
    } catch (error) {
      alert('Failed to create coupon');
    }
    setLoading(false);
  };

  const toggleCoupon = async (couponId, isActive) => {
    try {
      const token = localStorage.getItem('token');
      await fetch(`${API_BASE}/api/admin/coupons/${couponId}/toggle`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ isActive: !isActive })
      });
      fetchData();
    } catch (error) {
      alert('Failed to toggle coupon');
    }
  };

  const fetchCouponReport = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/api/admin/coupons/report`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setCouponReport(data);
      setShowReport(true);
    } catch (error) {
      alert('Failed to fetch coupon report');
    }
  };

  const updateShipping = async () => {
    try {
      const token = localStorage.getItem('token');
      await fetch(`${API_BASE}/api/admin/shipping`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ cost: shippingCost })
      });
      alert('Shipping cost updated!');
    } catch (error) {
      alert('Failed to update shipping cost');
    }
  };

  const updateBanner = async () => {
    try {
      const token = localStorage.getItem('token');
      await fetch(`${API_BASE}/api/admin/banner`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(bannerForm)
      });
      alert('Banner updated successfully!');
    } catch (error) {
      alert('Failed to update banner');
    }
  };

  const applyUserFilters = (filters) => {
    let filtered = [...users];

    // Search filter
    if (filters.search) {
      filtered = filtered.filter(user => 
        user.name.toLowerCase().includes(filters.search.toLowerCase()) ||
        user.email.toLowerCase().includes(filters.search.toLowerCase())
      );
    }

    // User type filter
    if (filters.userType === 'admin') {
      filtered = filtered.filter(user => user.email === 'admin@samriddhishop.com');
    } else if (filters.userType === 'user') {
      filtered = filtered.filter(user => user.email !== 'admin@samriddhishop.com');
    }

    // Sort filter
    filtered.sort((a, b) => {
      switch (filters.sortBy) {
        case 'email':
          return a.email.localeCompare(b.email);
        case 'orders-high':
          return (b.orderCount || 0) - (a.orderCount || 0);
        case 'amount-high':
          return (b.totalAmount || 0) - (a.totalAmount || 0);
        case 'date-new':
          return new Date(b.createdAt) - new Date(a.createdAt);
        case 'date-old':
          return new Date(a.createdAt) - new Date(b.createdAt);
        case 'name':
        default:
          return a.name.localeCompare(b.name);
      }
    });

    setFilteredUsers(filtered);
  };

  if (user?.email !== 'admin@samriddhishop.com') {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-red-600">Access Denied</h2>
        <p className="text-gray-600 mt-2">Admin access required</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="flex">
        {/* Sidebar */}
        <div className={`${sidebarOpen ? 'w-64' : 'w-16'} bg-white shadow-lg min-h-screen transition-all duration-300`}>
          <div className="p-6 border-b flex items-center justify-between">
            {sidebarOpen && <h1 className="text-xl font-bold text-gray-900">🛠️ Admin</h1>}
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
            >
              {sidebarOpen ? '←' : '→'}
            </button>
          </div>
          <nav className="p-4">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: '📊' },
              { id: 'products', label: 'Products', icon: '📦' },
              { id: 'orders', label: 'Orders', icon: '🛒' },
              { id: 'users', label: 'Users', icon: '👥' },
              { id: 'messages', label: 'Messages', icon: '💬' },
              { id: 'coupons', label: 'Coupons', icon: '🎫' },
              { id: 'banner', label: 'Banner', icon: '🖼️' },
              { id: 'settings', label: 'Settings', icon: '⚙️' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center ${sidebarOpen ? 'space-x-3' : 'justify-center'} px-4 py-3 rounded-lg mb-2 font-medium transition-all duration-200 ${
                  activeTab === tab.id 
                    ? 'bg-blue-50 text-blue-700 border-l-4 border-blue-500' 
                    : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                }`}
                title={!sidebarOpen ? tab.label : ''}
              >
                <div className="relative group">
                  <span className="text-lg">{tab.icon}</span>
                  {!sidebarOpen && (
                    <div className="absolute left-full ml-2 px-2 py-1 bg-gray-800 text-white text-sm rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap z-10">
                      {tab.label}
                    </div>
                  )}
                </div>
                {sidebarOpen && <span>{tab.label}</span>}
              </button>
            ))}
          </nav>
        </div>
        
        {/* Main Content */}
        <div className="flex-1 p-8">
          <div className="bg-white rounded-lg shadow-sm border p-6">
            {/* Dashboard Tab */}
            {activeTab === 'dashboard' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold">Dashboard Overview</h3>
                
                {/* Analytics Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  <div className="bg-blue-50 p-6 rounded-lg">
                    <h4 className="text-blue-800 font-semibold">Today's Orders</h4>
                    <p className="text-2xl font-bold text-blue-600">{analytics.todayOrders || 0}</p>
                  </div>
                  <div className="bg-green-50 p-6 rounded-lg">
                    <h4 className="text-green-800 font-semibold">This Week</h4>
                    <p className="text-2xl font-bold text-green-600">{analytics.weekOrders || 0}</p>
                  </div>
                  <div className="bg-purple-50 p-6 rounded-lg">
                    <h4 className="text-purple-800 font-semibold">This Month</h4>
                    <p className="text-2xl font-bold text-purple-600">{analytics.monthOrders || 0}</p>
                  </div>
                  <div className="bg-yellow-50 p-6 rounded-lg">
                    <h4 className="text-yellow-800 font-semibold">Total Revenue</h4>
                    <p className="text-2xl font-bold text-yellow-600">₹{(analytics.totalRevenue || 0).toLocaleString()}</p>
                  </div>
                </div>
                
                {/* Status Distribution */}
                <div className="bg-gray-50 p-6 rounded-lg">
                  <h4 className="font-semibold mb-4">Order Status Distribution</h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {analytics.statusCounts?.map(status => (
                      <div key={status._id} className="text-center">
                        <p className="text-lg font-bold">{status.count}</p>
                        <p className="text-sm text-gray-600 capitalize">{status._id}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
            
            {/* Products Tab */}
            {activeTab === 'products' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-lg font-semibold">Products Management</h3>
                  <button
                    onClick={() => setShowProductForm(true)}
                    className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    + Add New Product
                  </button>
                </div>
                
                {/* Product Form Modal */}
                {showProductForm && (
                  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                    <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
                      <div className="p-6">
                        <div className="flex justify-between items-center mb-4">
                          <h3 className="text-lg font-semibold">{editingProduct ? 'Edit Product' : 'Add New Product'}</h3>
                          <button
                            onClick={() => {
                              setShowProductForm(false);
                              setEditingProduct(null);
                              setProductForm({ name: '', description: '', price: '', originalPrice: '', discountPercentage: '', imageUrl: '', category: '', stock: '', variants: [], highlights: [], specifications: [], warranty: '', images: [], showHighlights: false, showSpecifications: false, showWarranty: false });
                            }}
                            className="text-gray-500 hover:text-gray-700"
                          >
                            ✕
                          </button>
                        </div>
                        <div className="space-y-6">
                          {/* Basic Info */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <input
                              type="text"
                              placeholder="Product Name"
                              value={productForm.name}
                              onChange={(e) => setProductForm({...productForm, name: e.target.value})}
                              className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                            <input
                              type="text"
                              placeholder="Category"
                              value={productForm.category}
                              onChange={(e) => setProductForm({...productForm, category: e.target.value})}
                              className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                            <input
                              type="number"
                              placeholder="Original Price (₹)"
                              value={productForm.originalPrice}
                              onChange={(e) => {
                                const originalPrice = parseFloat(e.target.value) || 0;
                                const discount = parseFloat(productForm.discountPercentage) || 0;
                                const sellingPrice = Math.round(originalPrice - (originalPrice * discount / 100));
                                setProductForm({...productForm, originalPrice: e.target.value, price: sellingPrice > 0 ? sellingPrice.toString() : ''});
                              }}
                              className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                            <input
                              type="number"
                              placeholder="Discount %"
                              value={productForm.discountPercentage}
                              onChange={(e) => {
                                const discount = parseFloat(e.target.value) || 0;
                                const originalPrice = parseFloat(productForm.originalPrice) || 0;
                                const sellingPrice = Math.round(originalPrice - (originalPrice * discount / 100));
                                setProductForm({...productForm, discountPercentage: e.target.value, price: sellingPrice > 0 ? sellingPrice.toString() : ''});
                              }}
                              className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                              min="0"
                              max="100"
                            />
                            <input
                              type="number"
                              placeholder="Selling Price (₹) - Auto calculated"
                              value={productForm.price}
                              className="px-4 py-2 border rounded-lg bg-gray-50"
                              readOnly
                            />
                            <input
                              type="number"
                              placeholder="Stock"
                              value={productForm.stock}
                              onChange={(e) => setProductForm({...productForm, stock: e.target.value})}
                              className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                          </div>
                          
                          <textarea
                            placeholder="Product Description"
                            value={productForm.description}
                            onChange={(e) => setProductForm({...productForm, description: e.target.value})}
                            className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 h-24"
                          />
                          
                          {/* Images */}
                          <div>
                            <h4 className="font-medium mb-2">Product Images</h4>
                            <div className="space-y-2">
                              <input
                                type="url"
                                placeholder="Main Image URL"
                                value={productForm.imageUrl}
                                onChange={(e) => setProductForm({...productForm, imageUrl: e.target.value})}
                                className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                              />
                              {productForm.images.map((img, index) => (
                                <div key={index} className="flex space-x-2">
                                  <input
                                    type="url"
                                    placeholder={`Additional Image ${index + 1} URL`}
                                    value={img}
                                    onChange={(e) => {
                                      const newImages = [...productForm.images];
                                      newImages[index] = e.target.value;
                                      setProductForm({...productForm, images: newImages});
                                    }}
                                    className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                                  />
                                  <button
                                    type="button"
                                    onClick={() => {
                                      const newImages = productForm.images.filter((_, i) => i !== index);
                                      setProductForm({...productForm, images: newImages});
                                    }}
                                    className="text-red-600 hover:text-red-800 px-2"
                                  >
                                    Remove
                                  </button>
                                </div>
                              ))}
                              <button
                                type="button"
                                onClick={() => setProductForm({...productForm, images: [...productForm.images, '']})}
                                className="text-blue-600 hover:text-blue-800 text-sm"
                              >
                                + Add Another Image
                              </button>
                            </div>
                          </div>
                          
                          {/* Highlights */}
                          <div>
                            <div className="flex items-center space-x-2 mb-2">
                              <input
                                type="checkbox"
                                checked={productForm.showHighlights}
                                onChange={(e) => setProductForm({...productForm, showHighlights: e.target.checked})}
                                className="rounded"
                              />
                              <h4 className="font-medium">Product Highlights</h4>
                            </div>
                            {productForm.showHighlights && (
                              <div className="space-y-2">
                                <div className="flex space-x-2">
                                  <input
                                    type="text"
                                    placeholder="Add highlight"
                                    value={newHighlight}
                                    onChange={(e) => setNewHighlight(e.target.value)}
                                    className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                                  />
                                  <button
                                    type="button"
                                    onClick={() => {
                                      if (newHighlight.trim()) {
                                        setProductForm({...productForm, highlights: [...productForm.highlights, newHighlight.trim()]});
                                        setNewHighlight('');
                                      }
                                    }}
                                    className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700"
                                  >
                                    Add
                                  </button>
                                </div>
                                {productForm.highlights.map((highlight, index) => (
                                  <div key={index} className="flex items-center justify-between bg-gray-50 p-2 rounded">
                                    <span>{highlight}</span>
                                    <button
                                      type="button"
                                      onClick={() => {
                                        const newHighlights = productForm.highlights.filter((_, i) => i !== index);
                                        setProductForm({...productForm, highlights: newHighlights});
                                      }}
                                      className="text-red-600 hover:text-red-800 text-sm"
                                    >
                                      Remove
                                    </button>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                          
                          {/* Specifications */}
                          <div>
                            <div className="flex items-center space-x-2 mb-2">
                              <input
                                type="checkbox"
                                checked={productForm.showSpecifications}
                                onChange={(e) => setProductForm({...productForm, showSpecifications: e.target.checked})}
                                className="rounded"
                              />
                              <h4 className="font-medium">Product Specifications</h4>
                            </div>
                            {productForm.showSpecifications && (
                              <div className="space-y-2">
                                <div className="grid grid-cols-2 gap-2">
                                  <input
                                    type="text"
                                    placeholder="Specification name"
                                    value={newSpec.key}
                                    onChange={(e) => setNewSpec({...newSpec, key: e.target.value})}
                                    className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                                  />
                                  <div className="flex space-x-2">
                                    <input
                                      type="text"
                                      placeholder="Specification value"
                                      value={newSpec.value}
                                      onChange={(e) => setNewSpec({...newSpec, value: e.target.value})}
                                      className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                    <button
                                      type="button"
                                      onClick={() => {
                                        if (newSpec.key.trim() && newSpec.value.trim()) {
                                          setProductForm({...productForm, specifications: [...productForm.specifications, {key: newSpec.key.trim(), value: newSpec.value.trim()}]});
                                          setNewSpec({key: '', value: ''});
                                        }
                                      }}
                                      className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700"
                                    >
                                      Add
                                    </button>
                                  </div>
                                </div>
                                {productForm.specifications.map((spec, index) => (
                                  <div key={index} className="flex items-center justify-between bg-gray-50 p-2 rounded">
                                    <span><strong>{spec.key}:</strong> {spec.value}</span>
                                    <button
                                      type="button"
                                      onClick={() => {
                                        const newSpecs = productForm.specifications.filter((_, i) => i !== index);
                                        setProductForm({...productForm, specifications: newSpecs});
                                      }}
                                      className="text-red-600 hover:text-red-800 text-sm"
                                    >
                                      Remove
                                    </button>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                          
                          {/* Warranty */}
                          <div>
                            <div className="flex items-center space-x-2 mb-2">
                              <input
                                type="checkbox"
                                checked={productForm.showWarranty}
                                onChange={(e) => setProductForm({...productForm, showWarranty: e.target.checked})}
                                className="rounded"
                              />
                              <h4 className="font-medium">Warranty Information</h4>
                            </div>
                            {productForm.showWarranty && (
                              <textarea
                                placeholder="Warranty details and terms"
                                value={productForm.warranty}
                                onChange={(e) => setProductForm({...productForm, warranty: e.target.value})}
                                className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 h-20"
                              />
                            )}
                          </div>
                  
                  {/* Variants Section */}
                  <div className="mt-6">
                    <h4 className="font-semibold mb-3">Product Variants (Size & Color)</h4>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                      <input
                        type="text"
                        placeholder="Size (S, M, L, XL)"
                        value={newVariant.size}
                        onChange={(e) => setNewVariant({...newVariant, size: e.target.value})}
                        className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <input
                        type="text"
                        placeholder="Color"
                        value={newVariant.color}
                        onChange={(e) => setNewVariant({...newVariant, color: e.target.value})}
                        className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <input
                        type="number"
                        placeholder="Stock"
                        value={newVariant.stock}
                        onChange={(e) => setNewVariant({...newVariant, stock: e.target.value})}
                        className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <button
                        type="button"
                        onClick={() => {
                          if (newVariant.size && newVariant.color && newVariant.stock) {
                            setProductForm({...productForm, variants: [...productForm.variants, newVariant]});
                            setNewVariant({ size: '', color: '', stock: '' });
                          }
                        }}
                        className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700"
                      >
                        Add Variant
                      </button>
                    </div>
                    
                    {/* Display Added Variants */}
                    {productForm.variants.length > 0 && (
                      <div className="space-y-2">
                        <h5 className="font-medium">Added Variants:</h5>
                        {productForm.variants.map((variant, index) => (
                          <div key={index} className="flex items-center justify-between bg-gray-50 p-3 rounded">
                            <span>Size: {variant.size} | Color: {variant.color} | Stock: {variant.stock}</span>
                            <button
                              type="button"
                              onClick={() => {
                                const newVariants = productForm.variants.filter((_, i) => i !== index);
                                setProductForm({...productForm, variants: newVariants});
                              }}
                              className="text-red-600 hover:text-red-800"
                            >
                              Remove
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                        </div>
                        
                        <div className="flex space-x-3 mt-6 pt-4 border-t">
                          <button
                            onClick={saveProduct}
                            disabled={loading}
                            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
                          >
                            {loading ? 'Saving...' : editingProduct ? 'Update Product' : 'Add Product'}
                          </button>
                          <button
                            onClick={() => {
                              setShowProductForm(false);
                              setEditingProduct(null);
                              setProductForm({ name: '', description: '', price: '', originalPrice: '', discountPercentage: '', imageUrl: '', category: '', stock: '', variants: [], highlights: [], specifications: [], warranty: '', images: [], showHighlights: false, showSpecifications: false, showWarranty: false });
                            }}
                            className="bg-gray-500 text-white px-6 py-2 rounded-lg hover:bg-gray-600"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Products List</h3>
                  {products.map(product => (
                    <div key={product._id} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center space-x-4">
                        <img src={product.imageUrl} alt={product.name} className="w-16 h-16 object-cover rounded" />
                        <div>
                          <h4 className="font-medium">{product.name}</h4>
                          <p className="text-gray-600">
                            ₹{product.price}
                            {product.originalPrice && product.discountPercentage > 0 && (
                              <span className="text-red-600 ml-2">({product.discountPercentage}% OFF)</span>
                            )}
                            | Stock: {product.stock}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <button
                          onClick={() => {
                            setEditingProduct(product);
                            setProductForm({
                              name: product.name,
                              description: product.description,
                              price: product.price.toString(),
                              originalPrice: product.originalPrice?.toString() || '',
                              discountPercentage: product.discountPercentage?.toString() || '',
                              imageUrl: product.imageUrl,
                              category: product.category,
                              stock: product.stock.toString(),
                              variants: product.variants || [],
                              highlights: product.highlights || [],
                              specifications: product.specifications || [],
                              warranty: product.warranty || '',
                              images: product.images || [],
                              showHighlights: product.showHighlights || false,
                              showSpecifications: product.showSpecifications || false,
                              showWarranty: product.showWarranty || false
                            });
                            setShowProductForm(true);
                          }}
                          className="text-blue-600 hover:text-blue-800"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => toggleProduct(product._id, product.enabled)}
                          className={`px-3 py-1 rounded text-sm ${
                            product.enabled !== false ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}
                        >
                          {product.enabled !== false ? 'Enabled' : 'Disabled'}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Users Tab */}
            {activeTab === 'users' && (
              <div className="space-y-6">
                <div className="flex flex-col md:flex-row md:justify-between md:items-center space-y-3 md:space-y-0">
                  <h3 className="text-lg font-semibold">User Management</h3>
                  <div className="flex flex-col md:flex-row space-y-2 md:space-y-0 md:space-x-3">
                    <div className="bg-blue-50 px-4 py-2 rounded-lg">
                      <span className="text-blue-800 font-medium">Total Users: {filteredUsers.length}</span>
                    </div>
                    <button
                      onClick={() => {
                        const csvContent = "data:text/csv;charset=utf-8," + 
                          "Name,Email,Phone,User Type,Join Date,Orders,Total Amount\n" +
                          filteredUsers.map(user => 
                            `"${user.name}","${user.email}","${user.phone || 'N/A'}","${user.email === 'admin@samriddhishop.com' ? 'Admin' : 'User'}","${new Date(user.createdAt).toLocaleDateString('en-IN')}","${user.orderCount || 0}","₹${user.totalAmount || 0}"`
                          ).join("\n");
                        const encodedUri = encodeURI(csvContent);
                        const link = document.createElement("a");
                        link.setAttribute("href", encodedUri);
                        link.setAttribute("download", `users_${new Date().toISOString().split('T')[0]}.csv`);
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                      }}
                      className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors"
                    >
                      📊 Export Excel
                    </button>
                  </div>
                </div>
                
                {/* User Filters */}
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                      <label className="block text-sm font-medium mb-1">Search</label>
                      <input
                        type="text"
                        placeholder="Search by name or email..."
                        value={userFilters.search}
                        onChange={(e) => {
                          const newFilters = {...userFilters, search: e.target.value};
                          setUserFilters(newFilters);
                          applyUserFilters(newFilters);
                        }}
                        className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-1">User Type</label>
                      <select
                        value={userFilters.userType}
                        onChange={(e) => {
                          const newFilters = {...userFilters, userType: e.target.value};
                          setUserFilters(newFilters);
                          applyUserFilters(newFilters);
                        }}
                        className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="all">All Users</option>
                        <option value="admin">Admin</option>
                        <option value="user">Regular Users</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-1">Sort By</label>
                      <select
                        value={userFilters.sortBy}
                        onChange={(e) => {
                          const newFilters = {...userFilters, sortBy: e.target.value};
                          setUserFilters(newFilters);
                          applyUserFilters(newFilters);
                        }}
                        className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="name">Name</option>
                        <option value="email">Email</option>
                        <option value="orders-high">Highest Orders</option>
                        <option value="amount-high">Highest Amount</option>
                        <option value="date-new">Newest First</option>
                        <option value="date-old">Oldest First</option>
                      </select>
                    </div>
                    <div className="flex items-end">
                      <button
                        onClick={() => {
                          setUserFilters({ search: '', userType: 'all', sortBy: 'name' });
                          setFilteredUsers(users);
                        }}
                        className="w-full bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600 transition-colors"
                      >
                        Clear Filters
                      </button>
                    </div>
                  </div>
                </div>
                
                <div className="bg-white border rounded-lg overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Name</th>
                          <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Email</th>
                          <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Phone</th>
                          <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Type</th>
                          <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Joined</th>
                          <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Orders</th>
                          <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Total Amount</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {filteredUsers.map(user => (
                          <tr key={user._id} className="hover:bg-gray-50">
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{user.name}</td>
                            <td className="px-4 py-3 text-sm text-gray-600 break-words">{user.email}</td>
                            <td className="px-4 py-3 text-sm text-gray-600">{user.phone || 'Not provided'}</td>
                            <td className="px-4 py-3 text-sm">
                              <span className={`px-2 py-1 rounded text-xs ${
                                user.email === 'admin@samriddhishop.com' 
                                  ? 'bg-red-100 text-red-800' 
                                  : 'bg-blue-100 text-blue-800'
                              }`}>
                                {user.email === 'admin@samriddhishop.com' ? 'Admin' : 'User'}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-600">{new Date(user.createdAt).toLocaleDateString('en-IN')}</td>
                            <td className="px-4 py-3 text-sm text-gray-600">{user.orderCount || 0}</td>
                            <td className="px-4 py-3 text-sm text-gray-600">₹{(user.totalAmount || 0).toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
                
                {filteredUsers.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    <p>No users found</p>
                  </div>
                )}
              </div>
            )}
            
            {/* Orders Tab */}
            {activeTab === 'orders' && (
              <div className="space-y-6">
                <div className="flex flex-col md:flex-row md:justify-between md:items-center space-y-3 md:space-y-0">
                  <h3 className="text-lg font-semibold">Order Management</h3>
                  <button
                    onClick={fetchOrdersByDate}
                    className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 w-full md:w-auto"
                  >
                    Apply Filters
                  </button>
                </div>
                
                {/* Date Filters */}
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                      <label className="block text-sm font-medium mb-1">Start Date</label>
                      <input
                        type="date"
                        value={dateFilter.startDate}
                        onChange={(e) => setDateFilter({...dateFilter, startDate: e.target.value})}
                        className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-1">End Date</label>
                      <input
                        type="date"
                        value={dateFilter.endDate}
                        onChange={(e) => setDateFilter({...dateFilter, endDate: e.target.value})}
                        className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-1">Status</label>
                      <select
                        value={dateFilter.status}
                        onChange={(e) => setDateFilter({...dateFilter, status: e.target.value})}
                        className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="all">All Status</option>
                        <option value="pending">Pending</option>
                        <option value="processing">Processing</option>
                        <option value="shipped">Shipped</option>
                        <option value="delivered">Delivered</option>
                      </select>
                    </div>
                  </div>
                </div>
                
                {/* Orders List */}
                <div className="space-y-4">
                  {orders.map(order => (
                    <div key={order._id} className="border rounded-lg p-4">
                      <div className="flex flex-col md:flex-row md:justify-between md:items-start space-y-3 md:space-y-0 mb-3">
                        <div className="flex-1">
                          <h4 className="font-medium">Order #{order.orderNumber || order._id.slice(-8)}</h4>
                          <p className="text-gray-600">₹{order.total} | {new Date(order.createdAt).toLocaleDateString()}</p>
                          <p className="text-sm text-gray-500 break-words">Customer: {order.userId?.name} ({order.userId?.email})</p>
                          {order.courierDetails?.trackingNumber && (
                            <p className="text-sm text-blue-600 break-words">Tracking: {order.courierDetails.trackingNumber} | {order.courierDetails.courierName}</p>
                          )}
                        </div>
                        <div className="flex flex-col md:flex-row items-start md:items-center space-y-2 md:space-y-0 md:space-x-3">
                          <select
                            value={order.status}
                            onChange={(e) => handleStatusChange(order._id, e.target.value)}
                            className="w-full md:w-auto px-3 py-1 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                          >
                            <option value="pending">Pending</option>
                            <option value="processing">Processing</option>
                            <option value="shipped">Shipped</option>
                            <option value="delivered">Delivered</option>
                          </select>
                          <span className={`px-2 py-1 rounded text-xs whitespace-nowrap ${
                            order.status === 'delivered' ? 'bg-green-100 text-green-800' :
                            order.status === 'shipped' ? 'bg-blue-100 text-blue-800' :
                            order.status === 'processing' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {order.status.toUpperCase()}
                          </span>
                        </div>
                      </div>
                      <div className="text-sm text-gray-600 break-words">
                        Items: {order.items.map(item => 
                          `${item.name}${item.selectedVariant ? ` (${item.selectedVariant.size}-${item.selectedVariant.color})` : ''} (${item.quantity})`
                        ).join(', ')}
                      </div>
                      {order.shippingAddress && (
                        <div className="text-sm text-gray-600 mt-2 break-words">
                          Address: {order.shippingAddress.street}, {order.shippingAddress.city}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
                
                {/* Courier Details Modal */}
                {selectedOrder && (
                  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-white p-6 rounded-lg max-w-md w-full mx-4">
                      <h3 className="text-lg font-semibold mb-4">Add Courier Details</h3>
                      <div className="space-y-4">
                        <div>
                          <label className="block text-sm font-medium mb-1">Courier Name</label>
                          <select
                            value={courierForm.courierName}
                            onChange={(e) => setCourierForm({...courierForm, courierName: e.target.value})}
                            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                          >
                            <option value="">Select Courier</option>
                            <option value="Blue Dart">Blue Dart</option>
                            <option value="DTDC">DTDC</option>
                            <option value="FedEx">FedEx</option>
                            <option value="Delhivery">Delhivery</option>
                            <option value="Ekart">Ekart</option>
                            <option value="India Post">India Post</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1">Tracking Number</label>
                          <input
                            type="text"
                            value={courierForm.trackingNumber}
                            onChange={(e) => setCourierForm({...courierForm, trackingNumber: e.target.value})}
                            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="Enter tracking number"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1">Estimated Delivery</label>
                          <input
                            type="date"
                            value={courierForm.estimatedDelivery}
                            onChange={(e) => setCourierForm({...courierForm, estimatedDelivery: e.target.value})}
                            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1">Notes</label>
                          <textarea
                            value={courierForm.notes}
                            onChange={(e) => setCourierForm({...courierForm, notes: e.target.value})}
                            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500 h-20"
                            placeholder="Additional notes..."
                          />
                        </div>
                      </div>
                      <div className="flex space-x-3 mt-6">
                        <button
                          onClick={() => setSelectedOrder(null)}
                          className="flex-1 bg-gray-500 text-white py-2 rounded hover:bg-gray-600"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={() => updateOrderStatus(selectedOrder, 'shipped', true)}
                          className="flex-1 bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
                        >
                          Ship Order
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
            
            {/* Coupons Tab */}
            {activeTab === 'coupons' && (
              <div className="space-y-6">
                <div className="bg-gray-50 p-6 rounded-lg">
                  <h3 className="text-lg font-semibold mb-4">Create New Coupon</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <input
                      type="text"
                      placeholder="Coupon Code"
                      value={couponForm.code}
                      onChange={(e) => setCouponForm({...couponForm, code: e.target.value.toUpperCase()})}
                      className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <input
                      type="number"
                      placeholder="Discount Value"
                      value={couponForm.discount}
                      onChange={(e) => setCouponForm({...couponForm, discount: e.target.value})}
                      className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <select
                      value={couponForm.type}
                      onChange={(e) => setCouponForm({...couponForm, type: e.target.value})}
                      className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="percentage">Percentage</option>
                      <option value="fixed">Fixed Amount</option>
                    </select>
                    <input
                      type="number"
                      placeholder="Minimum Amount"
                      value={couponForm.minAmount}
                      onChange={(e) => setCouponForm({...couponForm, minAmount: e.target.value})}
                      className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <input
                      type="date"
                      value={couponForm.expiryDate}
                      onChange={(e) => setCouponForm({...couponForm, expiryDate: e.target.value})}
                      className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <label className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={couponForm.oneTimeUse}
                        onChange={(e) => setCouponForm({...couponForm, oneTimeUse: e.target.checked})}
                        className="rounded"
                      />
                      <span>One-time use per user</span>
                    </label>
                  </div>
                  <button
                    onClick={saveCoupon}
                    disabled={loading}
                    className="mt-4 bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700 disabled:opacity-50"
                  >
                    {loading ? 'Creating...' : 'Create Coupon'}
                  </button>
                </div>
                
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-semibold">Coupon Management</h3>
                    <button
                      onClick={fetchCouponReport}
                      className="bg-purple-600 text-white px-4 py-2 rounded-lg hover:bg-purple-700"
                    >
                      Usage Report
                    </button>
                  </div>
                  {coupons.map(coupon => (
                    <div key={coupon._id} className="flex justify-between items-center p-4 border rounded-lg">
                      <div>
                        <h4 className="font-medium">{coupon.code}</h4>
                        <p className="text-gray-600">
                          {coupon.type === 'percentage' ? `${coupon.discount}% off` : `₹${coupon.discount} off`}
                          {coupon.minAmount && ` | Min: ₹${coupon.minAmount}`}
                          {coupon.oneTimeUse && ' | One-time use'}
                        </p>
                        <p className="text-sm text-gray-500">Used: {coupon.usageCount || 0} times</p>
                      </div>
                      <div className="flex items-center space-x-3">
                        <button
                          onClick={() => toggleCoupon(coupon._id, coupon.isActive)}
                          className={`px-3 py-1 rounded text-sm ${
                            coupon.isActive ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}
                        >
                          {coupon.isActive ? 'Enabled' : 'Disabled'}
                        </button>
                        <span className={`px-3 py-1 rounded text-sm ${
                          new Date(coupon.expiryDate) > new Date() ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'
                        }`}>
                          {new Date(coupon.expiryDate) > new Date() ? 'Valid' : 'Expired'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
                
                {/* Coupon Usage Report Modal */}
                {showReport && (
                  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-white p-6 rounded-lg max-w-4xl w-full mx-4 max-h-96 overflow-y-auto">
                      <div className="flex justify-between items-center mb-4">
                        <h3 className="text-lg font-semibold">Coupon Usage Report</h3>
                        <button
                          onClick={() => setShowReport(false)}
                          className="text-gray-500 hover:text-gray-700"
                        >
                          ✕
                        </button>
                      </div>
                      <div className="space-y-4">
                        {couponReport.map(coupon => (
                          <div key={coupon._id} className="border p-4 rounded">
                            <h4 className="font-medium mb-2">{coupon.code} - Used {coupon.usageCount} times</h4>
                            {coupon.usedBy.length > 0 ? (
                              <div className="space-y-2">
                                {coupon.usedBy.map((usage, index) => (
                                  <div key={index} className="text-sm bg-gray-50 p-2 rounded">
                                    <span className="font-medium">{usage.userId?.name}</span> ({usage.userId?.email})
                                    <span className="text-gray-500 ml-2">
                                      Order: {usage.orderId?.orderNumber} | 
                                      {new Date(usage.usedAt).toLocaleDateString()}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-gray-500 text-sm">No usage yet</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
            
            {/* Banner Tab */}
            {activeTab === 'banner' && (
              <div className="space-y-6">
                <div className="bg-gray-50 p-6 rounded-lg">
                  <h3 className="text-lg font-semibold mb-4">Home Page Banner Settings</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium mb-1">Banner Title</label>
                      <input
                        type="text"
                        value={bannerForm.title}
                        onChange={(e) => setBannerForm({...bannerForm, title: e.target.value})}
                        className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Welcome to SamriddhiShop"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-1">Button Text</label>
                      <input
                        type="text"
                        value={bannerForm.buttonText}
                        onChange={(e) => setBannerForm({...bannerForm, buttonText: e.target.value})}
                        className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Shop Now"
                      />
                    </div>
                    <div className="md:col-span-2">
                      <label className="block text-sm font-medium mb-1">Banner Subtitle</label>
                      <input
                        type="text"
                        value={bannerForm.subtitle}
                        onChange={(e) => setBannerForm({...bannerForm, subtitle: e.target.value})}
                        className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Discover amazing products at great prices"
                      />
                    </div>
                    <div className="md:col-span-2">
                      <label className="block text-sm font-medium mb-1">Background Image URL</label>
                      <input
                        type="url"
                        value={bannerForm.backgroundImage}
                        onChange={(e) => setBannerForm({...bannerForm, backgroundImage: e.target.value})}
                        className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="https://example.com/banner-image.jpg"
                      />
                      <p className="text-gray-600 text-sm mt-1">Leave empty to use default gradient background</p>
                    </div>
                  </div>
                  <button
                    onClick={updateBanner}
                    className="mt-4 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700"
                  >
                    Update Banner
                  </button>
                </div>
              </div>
            )}
            
            {/* Messages Tab */}
            {activeTab === 'messages' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold">Contact Messages</h3>
                  <div className="bg-blue-50 px-4 py-2 rounded-lg">
                    <span className="text-blue-800 font-medium">Total Messages: {contacts.length}</span>
                  </div>
                </div>
                
                {contacts.length === 0 ? (
                  <div className="text-center py-12">
                    <div className="text-6xl mb-4">💬</div>
                    <h3 className="text-xl text-gray-600 mb-2">No Messages Yet</h3>
                    <p className="text-gray-500">Contact form messages will appear here</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {contacts.map(contact => (
                      <div key={contact._id} className="bg-white border rounded-lg p-6 hover:shadow-md transition-shadow">
                        <div className="flex justify-between items-start mb-4">
                          <div className="flex-1">
                            <div className="flex items-center space-x-3 mb-2">
                              <h4 className="font-semibold text-lg text-gray-800">{contact.name}</h4>
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                                contact.status === 'new' ? 'bg-green-100 text-green-800' :
                                contact.status === 'read' ? 'bg-blue-100 text-blue-800' :
                                'bg-gray-100 text-gray-800'
                              }`}>
                                {contact.status.toUpperCase()}
                              </span>
                            </div>
                            <p className="text-gray-600 text-sm mb-1">📧 {contact.email}</p>
                            <p className="text-gray-500 text-sm">🗺️ {new Date(contact.createdAt).toLocaleString('en-IN')}</p>
                          </div>
                        </div>
                        
                        <div className="mb-4">
                          <h5 className="font-medium text-gray-800 mb-2">📝 Subject: {contact.subject}</h5>
                          <div className="bg-gray-50 p-4 rounded-lg">
                            <p className="text-gray-700 whitespace-pre-wrap">{contact.message}</p>
                          </div>
                        </div>
                        
                        <div className="flex space-x-3">
                          <button 
                            onClick={() => window.open(`mailto:${contact.email}?subject=Re: ${contact.subject}`)}
                            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 text-sm"
                          >
                            📧 Reply
                          </button>
                          <button 
                            onClick={async () => {
                              try {
                                const token = localStorage.getItem('token');
                                await fetch(`${API_BASE}/admin/contacts/${contact._id}/status`, {
                                  method: 'PATCH',
                                  headers: {
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${token}`
                                  },
                                  body: JSON.stringify({ status: 'read' })
                                });
                                fetchData();
                              } catch (error) {
                                console.error('Error updating status:', error);
                              }
                            }}
                            className="bg-gray-500 text-white px-4 py-2 rounded-lg hover:bg-gray-600 text-sm"
                          >
                            ✓ Mark as Read
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            
            {/* Settings Tab */}
            {activeTab === 'settings' && (
              <div className="space-y-6">
                <div className="bg-gray-50 p-4 md:p-6 rounded-lg">
                  <h3 className="text-lg font-semibold mb-4">Shipping Settings</h3>
                  <div className="flex flex-col md:flex-row md:items-center space-y-3 md:space-y-0 md:space-x-4">
                    <label className="font-medium">Shipping Cost (₹):</label>
                    <input
                      type="number"
                      value={shippingCost}
                      onChange={(e) => setShippingCost(Number(e.target.value))}
                      className="px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 w-full md:w-32"
                    />
                    <button
                      onClick={updateShipping}
                      className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 w-full md:w-auto"
                    >
                      Update
                    </button>
                  </div>
                  <p className="text-gray-600 text-sm mt-2">Set to 0 for free shipping</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* Admin Notification */}
      {adminNotification && (
        <div className={`fixed top-4 right-4 text-white p-4 rounded-lg shadow-lg z-50 ${
          adminNotification.type === 'success' ? 'bg-green-500' : 'bg-red-500'
        }`}>
          <p className="font-semibold">{adminNotification.message}</p>
        </div>
      )}
    </div>
  );
}

// Wishlist Product Card Component
function WishlistProductCard({ product, addToCart, removeFromWishlist, setNotification }) {
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const images = [product.imageUrl, ...(product.images || [])].filter(Boolean);
  
  useEffect(() => {
    if (images.length > 1) {
      const interval = setInterval(() => {
        setCurrentImageIndex(prev => (prev + 1) % images.length);
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [images.length]);
  
  return (
    <div className="bg-white rounded-lg shadow hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2 group relative">
      <Link to={`/product/${product._id}`}>
        <div className="relative overflow-hidden rounded-t-lg">
          <img 
            src={images[currentImageIndex]} 
            alt={product.name}
            className="w-full h-48 object-cover transition-all duration-300 group-hover:scale-105"
          />
          {product.originalPrice && product.discountPercentage && product.discountPercentage > 0 && (
            <div className="absolute top-2 left-2 bg-red-500 text-white px-2 py-1 rounded text-xs font-bold">
              {product.discountPercentage}% OFF
            </div>
          )}
          {images.length > 1 && (
            <div className="absolute bottom-2 left-1/2 transform -translate-x-1/2 flex space-x-1">
              {images.map((_, index) => (
                <div
                  key={index}
                  className={`w-1.5 h-1.5 rounded-full ${
                    index === currentImageIndex ? 'bg-white' : 'bg-white bg-opacity-50'
                  }`}
                />
              ))}
            </div>
          )}
        </div>
      </Link>
      
      <div className="p-4">
        <Link to={`/product/${product._id}`}>
          <h3 className="font-semibold text-lg mb-2 group-hover:text-blue-600 transition-colors">{product.name}</h3>
          <p className="text-gray-600 text-sm mb-2">{product.description.substring(0, 100)}...</p>
        </Link>
      
        <div className="flex items-center mb-2">
          <div className="flex text-yellow-400 text-sm">
            {'★'.repeat(Math.floor(product.averageRating || 0))}{'☆'.repeat(5 - Math.floor(product.averageRating || 0))}
          </div>
          <span className="text-gray-500 text-xs ml-1">({product.totalRatings || 0})</span>
        </div>
        
        <div className="flex items-center space-x-2 mb-4">
          <span className="text-xl font-bold text-green-600">₹{product.price.toLocaleString()}</span>
          {product.originalPrice && product.discountPercentage && product.discountPercentage > 0 && (
            <span className="text-sm text-gray-500 line-through">₹{product.originalPrice.toLocaleString()}</span>
          )}
        </div>
        
        <div className="space-y-2">
          <button 
            onClick={() => {
              addToCart(product);
              setNotification && setNotification({ message: 'Added to cart', product: product.name });
              setTimeout(() => setNotification && setNotification(null), 3000);
            }}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors"
          >
            {t('Add to Cart')}
          </button>
          <button 
            onClick={() => removeFromWishlist(product._id)}
            className="w-full bg-red-100 text-red-600 py-2 px-4 rounded-lg hover:bg-red-200 transition-colors"
          >
            Remove from Wishlist
          </button>
        </div>
      </div>
    </div>
  );
}

// Wishlist Page Component
function WishlistPageComponent({ user, wishlistProducts, setWishlistProducts, setWishlistItems, addToCart, setNotification }) {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Data is now passed via props, so we just need to handle the loading state.
    setLoading(false);
  }, [wishlistProducts]);

  const removeFromWishlist = async (productId) => {
    try {
      const token = getToken();
      const response = await fetch(`${API_BASE}/api/wishlist/${productId}`, {
        method: 'DELETE',
        headers: { 
          'Authorization': `Bearer ${token}`,
          // Assuming you might add CSRF protection to this route later
          // 'X-CSRF-Token': await getCsrfToken() 
        }
      });
      
      if (response.ok) {
        setWishlistItems(prev => prev.filter(id => id !== productId));
        setWishlistProducts(prev => prev.filter(product => product._id !== productId));
      }
    } catch (error) {
      alert('Failed to remove item from wishlist.');
      console.error('Error removing from wishlist:', error);
    }
  };

  if (!user) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-gray-600 mb-4">Please login to view wishlist</h2>
        <Link to="/login" className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
          Login
        </Link>
      </div>
    );
  }

  if (loading) return <LoadingSpinner />;

  return (
    <div className="max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mb-8">My Wishlist</h1>
      
      {wishlistProducts.length === 0 ? (
        <div className="text-center py-12">
          <div className="text-6xl mb-4">❤️</div>
          <h2 className="text-xl text-gray-600 mb-4">Your wishlist is empty</h2>
          <p className="text-gray-500 mb-6">Add products you love to your wishlist</p>
          <Link to="/products" className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600">
            Browse Products
          </Link>
        </div>
      ) : (
        <>
          <p className="text-gray-600 mb-6">{wishlistProducts.length} item(s) in your wishlist</p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {wishlistProducts.map(product => (
              <WishlistProductCard 
                key={product._id} 
                product={product} 
                addToCart={addToCart}
                removeFromWishlist={removeFromWishlist}
                setNotification={setNotification}
              />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// Customer Service Page Component
function CustomerServicePage() {
  const [activeTab, setActiveTab] = useState('contact');
  const [contactForm, setContactForm] = useState({ name: '', email: '', subject: '', message: '' });
  const [loading, setLoading] = useState(false);

  const tabs = [
    { id: 'contact', label: 'Contact Us', icon: '📞' },
    { id: 'faq', label: 'FAQ', icon: '❓' },
    { id: 'returns', label: 'Returns', icon: '↩️' },
    { id: 'shipping', label: 'Shipping', icon: '🚚' }
  ];

  const faqs = [
    { q: 'How do I track my order?', a: 'You can track your order by visiting the "My Orders" section in your profile or using the tracking link sent to your email.' },
    { q: 'What payment methods do you accept?', a: 'We accept Cash on Delivery (COD). Credit/Debit cards and UPI payments are coming soon.' },
    { q: 'How long does delivery take?', a: 'Standard delivery takes 3-5 business days. Express delivery options are available for faster shipping.' },
    { q: 'Can I cancel my order?', a: 'Yes, you can cancel your order within 24 hours of placing it. Contact our support team for assistance.' },
    { q: 'What is your return policy?', a: 'You can return items within 5 days after delivery. Items must be unused and in original packaging.' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-50 py-8">
      <div className="max-w-6xl mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center space-x-2 text-blue-600 hover:text-blue-800 mb-4 transition-colors">
            <span>←</span>
            <span>Back to Home</span>
          </Link>
          <div className="w-20 h-20 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-full flex items-center justify-center mx-auto mb-4 shadow-lg">
            <span className="text-3xl text-white">🎧</span>
          </div>
          <h1 className="text-4xl font-bold text-gray-800 mb-2">Customer Service</h1>
          <p className="text-gray-600">We're here to help you with any questions or concerns</p>
        </div>

        <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
          {/* Navigation Tabs */}
          <div className="bg-gradient-to-r from-gray-50 to-blue-50 border-b">
            <nav className="flex overflow-x-auto">
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 px-6 py-4 font-medium whitespace-nowrap transition-all ${
                    activeTab === tab.id
                      ? 'border-b-3 border-blue-600 text-blue-600 bg-white shadow-sm'
                      : 'text-gray-600 hover:text-gray-800 hover:bg-white/50'
                  }`}
                >
                  <span className="text-lg">{tab.icon}</span>
                  <span>{tab.label}</span>
                </button>
              ))}
            </nav>
          </div>

          <div className="p-8">
            {/* Contact Us Tab */}
            {activeTab === 'contact' && (
              <div className="space-y-8">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                  {/* Contact Form */}
                  <div className="bg-gradient-to-br from-blue-50 to-indigo-50 p-6 rounded-xl">
                    <h2 className="text-2xl font-bold text-gray-800 mb-6 flex items-center space-x-2">
                      <span>📝</span>
                      <span>Send us a Message</span>
                    </h2>
                    <div className="space-y-4">
                      <input
                        type="text"
                        placeholder="Your Name"
                        value={contactForm.name}
                        onChange={(e) => setContactForm({...contactForm, name: e.target.value})}
                        className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <input
                        type="email"
                        placeholder="Your Email"
                        value={contactForm.email}
                        onChange={(e) => setContactForm({...contactForm, email: e.target.value})}
                        className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <input
                        type="text"
                        placeholder="Subject"
                        value={contactForm.subject}
                        onChange={(e) => setContactForm({...contactForm, subject: e.target.value})}
                        className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <textarea
                        placeholder="Your Message"
                        value={contactForm.message}
                        onChange={(e) => setContactForm({...contactForm, message: e.target.value})}
                        rows="4"
                        className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <button 
                        onClick={async () => {
                          if (!contactForm.name || !contactForm.email || !contactForm.message) {
                            alert('Please fill in all required fields');
                            return;
                          }
                          setLoading(true);
                          try {
                            const response = await fetch(`${API_BASE}/contact`, {
                              method: 'POST',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify(contactForm)
                            });
                            if (response.ok) {
                              alert('Message sent successfully! We\'ll get back to you soon.');
                              setContactForm({ name: '', email: '', subject: '', message: '' });
                            } else {
                              alert('Failed to send message. Please try again.');
                            }
                          } catch (error) {
                            alert('Failed to send message. Please try again.');
                          }
                          setLoading(false);
                        }}
                        disabled={loading}
                        className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-3 rounded-xl font-semibold hover:from-blue-700 hover:to-indigo-700 transition-all disabled:opacity-50"
                      >
                        {loading ? 'Sending...' : 'Send Message'}
                      </button>
                    </div>
                  </div>

                  {/* Contact Info */}
                  <div className="space-y-6">
                    <h2 className="text-2xl font-bold text-gray-800 mb-6">Get in Touch</h2>
                    <div className="space-y-4">
                      <div className="flex items-center space-x-4 p-4 bg-green-50 rounded-xl">
                        <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                          <span className="text-xl">📧</span>
                        </div>
                        <div>
                          <p className="font-semibold text-green-800">Email Support</p>
                          <p className="text-green-600">support@samriddhishop.com</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-4 p-4 bg-blue-50 rounded-xl">
                        <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                          <span className="text-xl">📱</span>
                        </div>
                        <div>
                          <p className="font-semibold text-blue-800">Phone Support</p>
                          <p className="text-blue-600">+91 9876543210</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-4 p-4 bg-purple-50 rounded-xl">
                        <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
                          <span className="text-xl">🕒</span>
                        </div>
                        <div>
                          <p className="font-semibold text-purple-800">Business Hours</p>
                          <p className="text-purple-600">Mon-Sat: 9AM-6PM</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* FAQ Tab */}
            {activeTab === 'faq' && (
              <div className="space-y-6">
                <h2 className="text-2xl font-bold text-gray-800 mb-6 flex items-center space-x-2">
                  <span>❓</span>
                  <span>Frequently Asked Questions</span>
                </h2>
                <div className="space-y-4">
                  {faqs.map((faq, index) => (
                    <div key={index} className="bg-gray-50 p-6 rounded-xl hover:bg-gray-100 transition-colors">
                      <h3 className="font-semibold text-gray-800 mb-2">{faq.q}</h3>
                      <p className="text-gray-600">{faq.a}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Returns Tab */}
            {activeTab === 'returns' && (
              <div className="space-y-8">
                <h2 className="text-2xl font-bold text-gray-800 mb-6 flex items-center space-x-2">
                  <span>↩️</span>
                  <span>Return Policy</span>
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div className="bg-green-50 p-6 rounded-xl">
                    <h3 className="text-xl font-bold text-green-800 mb-4">✅ Easy Returns</h3>
                    <ul className="space-y-2 text-green-700">
                      <li>• 5-day return window after delivery</li>
                      <li>• Free return shipping</li>
                      <li>• some questions asked for refund</li>
                      <li>• Full refund guarantee</li>
                    </ul>
                  </div>
                  <div className="bg-blue-50 p-6 rounded-xl">
                    <h3 className="text-xl font-bold text-blue-800 mb-4">📋 Return Process</h3>
                    <ol className="space-y-2 text-blue-700">
                      <li>1. Contact our support team</li>
                      <li>2. Receive return label</li>
                      <li>3. Pack and ship the item</li>
                      <li>4. Get your refund in 3-5 days</li>
                    </ol>
                  </div>
                </div>
                <div className="bg-yellow-50 p-6 rounded-xl">
                  <h3 className="text-xl font-bold text-yellow-800 mb-4">⚠️ Return Conditions</h3>
                  <p className="text-yellow-700">Items must be unused, in original packaging, and returned within 5 days of delivery. Some items like personalized products may not be eligible for return.</p>
                </div>
              </div>
            )}

            {/* Shipping Tab */}
            {activeTab === 'shipping' && (
              <div className="space-y-8">
                <h2 className="text-2xl font-bold text-gray-800 mb-6 flex items-center space-x-2">
                  <span>🚚</span>
                  <span>Shipping Information</span>
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-blue-50 p-6 rounded-xl text-center">
                    <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <span className="text-2xl">🚛</span>
                    </div>
                    <h3 className="text-lg font-bold text-blue-800 mb-2">Standard Delivery</h3>
                    <p className="text-blue-600 mb-2">3-5 Business Days</p>
                    <p className="text-sm text-blue-500">Free on orders over ₹500</p>
                  </div>
                  <div className="bg-green-50 p-6 rounded-xl text-center">
                    <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <span className="text-2xl">⚡</span>
                    </div>
                    <h3 className="text-lg font-bold text-green-800 mb-2">Express Delivery</h3>
                    <p className="text-green-600 mb-2">1-2 Business Days</p>
                    <p className="text-sm text-green-500">₹99 shipping fee</p>
                  </div>
                  <div className="bg-purple-50 p-6 rounded-xl text-center">
                    <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <span className="text-2xl">🏪</span>
                    </div>
                    <h3 className="text-lg font-bold text-purple-800 mb-2">Store Pickup</h3>
                    <p className="text-purple-600 mb-2">Same Day</p>
                    <p className="text-sm text-purple-500">Free pickup available</p>
                  </div>
                </div>
                <div className="bg-gray-50 p-6 rounded-xl">
                  <h3 className="text-xl font-bold text-gray-800 mb-4">📍 Delivery Areas</h3>
                  <p className="text-gray-600 mb-4">We currently deliver to all major cities across India. Remote areas may have extended delivery times.</p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div className="text-gray-700">• Mumbai</div>
                    <div className="text-gray-700">• Delhi</div>
                    <div className="text-gray-700">• Bangalore</div>
                    <div className="text-gray-700">• Chennai</div>
                    <div className="text-gray-700">• Kolkata</div>
                    <div className="text-gray-700">• Hyderabad</div>
                    <div className="text-gray-700">• Pune</div>
                    <div className="text-gray-700">• And 500+ more cities</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Footer Component
const Footer = React.memo(function Footer() {
  return (
    <footer className="bg-gray-800 text-white py-8 mt-12">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div>
            <h3 className="text-lg font-bold mb-4">SamriddhiShop</h3>
            <p className="text-gray-300 text-sm">Your trusted online shopping destination for quality products at great prices.</p>
          </div>
          
          <div>
            <h4 className="font-semibold mb-3">Quick Links</h4>
            <ul className="space-y-2 text-sm">
              <li><Link to="/" className="text-gray-300 hover:text-white">Home</Link></li>
              <li><Link to="/products" className="text-gray-300 hover:text-white">Products</Link></li>
              <li><Link to="/orders" className="text-gray-300 hover:text-white">My Orders</Link></li>
              <li><Link to="/wishlist" className="text-gray-300 hover:text-white">Wishlist</Link></li>
              <li><Link to="/profile" className="text-gray-300 hover:text-white">Profile</Link></li>
            </ul>
          </div>
          
          <div>
            <h4 className="font-semibold mb-3">Customer Service</h4>
            <ul className="space-y-2 text-sm">
              <li><Link to="/support" className="text-gray-300 hover:text-white">Contact Us</Link></li>
              <li><Link to="/support" className="text-gray-300 hover:text-white">FAQ</Link></li>
              <li><Link to="/support" className="text-gray-300 hover:text-white">Return Policy</Link></li>
              <li><a href="#" className="text-gray-300 hover:text-white">Shipping Info</a></li>
            </ul>
          </div>
          
          <div>
            <h4 className="font-semibold mb-3">Connect</h4>
            <ul className="space-y-2 text-sm">
              <li><a href="#" className="text-gray-300 hover:text-white">📧 support@samriddhishop.com</a></li>
              <li><a href="#" className="text-gray-300 hover:text-white">📞 +91 9876543210</a></li>
              <li><a href="#" className="text-gray-300 hover:text-white">📍 Mumbai, India</a></li>
            </ul>
          </div>
        </div>
        
        <div className="border-t border-gray-700 mt-8 pt-6 text-center text-sm text-gray-400">
          <p>&copy; 2024 SamriddhiShop. All rights reserved. | Built with ❤️ in India</p>
        </div>
      </div>
    </footer>
  );});

export default App;
