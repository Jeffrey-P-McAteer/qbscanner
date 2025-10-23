#pragma once

#include <vector>
#include <string>
#include <cmath>
#include <memory>

struct Color {
    unsigned char r, g, b, a;
    Color(unsigned char r = 0, unsigned char g = 0, unsigned char b = 0, unsigned char a = 255) : r(r), g(g), b(b), a(a) {}
    
    static Color white() { return Color(255, 255, 255, 255); }
    static Color black() { return Color(0, 0, 0, 255); }
    static Color red() { return Color(244, 67, 54, 255); }
    static Color green() { return Color(76, 175, 80, 255); }
    static Color blue() { return Color(33, 150, 243, 255); }
    static Color orange() { return Color(255, 152, 0, 255); }
    static Color purple() { return Color(156, 39, 176, 255); }
    static Color gray() { return Color(127, 140, 141, 255); }
    static Color darkGray() { return Color(44, 62, 80, 255); }
};

struct Point {
    double x, y;
    Point(double x = 0, double y = 0) : x(x), y(y) {}
};

struct Rect {
    double x, y, width, height;
    Rect(double x = 0, double y = 0, double w = 0, double h = 0) : x(x), y(y), width(w), height(h) {}
};

class BitmapRenderer {
private:
    int width, height;
    std::vector<unsigned char> pixels; // RGBA format
    std::vector<unsigned char> font_data;
    void* font_info = nullptr;
    bool font_loaded = false;
    
public:
    BitmapRenderer(int w, int h);
    ~BitmapRenderer();
    
    bool loadSystemFont();
    void clear(Color color = Color::white());
    void drawLine(Point start, Point end, Color color, float thickness = 1.0f);
    void drawCircle(Point center, double radius, Color fillColor, Color borderColor = Color::black(), float borderWidth = 1.0f);
    void drawRect(Rect rect, Color fillColor, Color borderColor = Color::black(), float borderWidth = 1.0f);
    void drawText(const std::string& text, Point position, float fontSize, Color color = Color::black(), bool bold = false);
    
    // Text measurement
    Point measureText(const std::string& text, float fontSize, bool bold = false);
    
    // Export
    bool savePNG(const std::string& filename);
    
private:
    void setPixel(int x, int y, Color color);
    Color getPixel(int x, int y) const;
    void blendPixel(int x, int y, Color color, float alpha = 1.0f);
    void drawCirclePoints(int cx, int cy, int x, int y, Color color);
    void drawThickLine(Point start, Point end, float thickness, Color color);
};